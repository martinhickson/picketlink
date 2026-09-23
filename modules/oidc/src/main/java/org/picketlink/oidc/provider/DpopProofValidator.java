package org.picketlink.oidc.provider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
import org.apache.cxf.rs.security.jose.jws.JwsCompactConsumer;

/**
 * DPoP proof validation (RFC 9449): a JWT with {@code typ: dpop+jwt}, signed by an
 * asymmetric key carried in the header's {@code jwk}, binding the HTTP method
 * ({@code htm}) and target URI ({@code htu}, no query/fragment) with a freshness window
 * and single-use {@code jti}. The key's RFC 7638 thumbprint ({@code jkt}) is embedded as
 * the token's {@code cnf.jkt} confirmation claim, making bearer replay useless — a stolen
 * DPoP-bound access token cannot be used without the client's private key.
 */
public final class DpopProofValidator {

    /** RFC 9449: proofs older than this are rejected (recommended challenge window). */
    public static final long DEFAULT_FRESHNESS_SECONDS = 30L;

    private final Clock clock;
    private final long freshnessSeconds;
    private final ConcurrentHashMap<String, Long> seenJti = new ConcurrentHashMap<>();

    public DpopProofValidator(Clock clock) {
        this(clock, DEFAULT_FRESHNESS_SECONDS);
    }

    public DpopProofValidator(Clock clock, long freshnessSeconds) {
        this.clock = clock;
        this.freshnessSeconds = freshnessSeconds;
    }

    /**
     * Validates a DPoP proof against the expected method/URI and returns the key
     * thumbprint to bind into the access token ({@code cnf.jkt}).
     *
     * @throws DpopValidationException when the proof is malformed, stale, replayed,
     *         method/URI-mismatched or badly signed
     */
    public String validate(String proof, String httpMethod, String targetUri) {
        JwsCompactConsumer consumer;
        try {
            consumer = new JwsCompactConsumer(proof);
        } catch (RuntimeException ex) {
            throw new DpopValidationException("malformed DPoP proof");
        }
        String typ = String.valueOf(consumer.getJwsHeaders().getHeader("typ"));
        if (!"dpop+jwt".equals(typ)) {
            throw new DpopValidationException("DPoP proof typ must be dpop+jwt");
        }
        SignatureAlgorithm algorithm = consumer.getJwsHeaders().getSignatureAlgorithm();
        String jwaName = algorithm == null ? null : algorithm.getJwaName();
        if (jwaName == null
                || jwaName.regionMatches(true, 0, "HS", 0, 2)
                || jwaName.regionMatches(true, 0, "none", 0, 4)) {
            throw new DpopValidationException("DPoP proof must use an asymmetric algorithm");
        }

        Object jwkHeader = consumer.getJwsHeaders().getHeader("jwk");
        if (jwkHeader == null) {
            throw new DpopValidationException("DPoP proof must carry the public key (jwk header)");
        }
        JsonWebKey jwk;
        try {
            String jwkJson = jwkHeader instanceof java.util.Map
                    ? new org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter()
                            .toJson((java.util.Map<String, Object>) jwkHeader)
                    : String.valueOf(jwkHeader);
            jwk = JwkUtils.readJwkKey(jwkJson);
        } catch (RuntimeException ex) {
            throw new DpopValidationException("invalid jwk in DPoP proof");
        }
        String jkt = thumbprint(jwk);

        PublicKey publicKey;
        try {
            publicKey = toPublicKey(jwk);
        } catch (RuntimeException ex) {
            throw new DpopValidationException("unsupported jwk key type");
        }
        if (!consumer.verifySignatureWith(publicKey, algorithm)) {
            throw new DpopValidationException("invalid DPoP proof signature");
        }

        org.apache.cxf.rs.security.jose.jwt.JwtClaims claims;
        try {
            claims = new org.apache.cxf.rs.security.jose.jwt.JwtClaims(
                    new org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter()
                            .fromJson(consumer.getDecodedJwsPayload()));
        } catch (RuntimeException ex) {
            throw new DpopValidationException("malformed DPoP payload");
        }
        if (!httpMethod.equalsIgnoreCase(String.valueOf(claims.getClaim("htm")))) {
            throw new DpopValidationException("DPoP htm does not match the request method");
        }
        if (!normalize(targetUri).equals(normalize(String.valueOf(claims.getClaim("htu"))))) {
            throw new DpopValidationException("DPoP htu does not match the request URI");
        }
        Long issuedAt = claims.getIssuedAt();
        long now = clock.instant().getEpochSecond();
        if (issuedAt == null || issuedAt < now - freshnessSeconds || issuedAt > now + freshnessSeconds) {
            throw new DpopValidationException("DPoP proof is stale");
        }
        String jti = claims.getTokenId();
        if (jti == null || jti.isBlank()) {
            throw new DpopValidationException("DPoP proof requires jti");
        }
        Long previous = seenJti.putIfAbsent(jti, now);
        if (previous != null) {
            throw new DpopValidationException("DPoP proof replayed");
        }
        evict(now);
        return jkt;
    }

    /** RFC 7638 thumbprint over the canonical JWK (required members, lexicographic). */
    static String thumbprint(JsonWebKey jwk) {
        StringBuilder canonical = new StringBuilder("{");
        if ("RSA".equals(String.valueOf(jwk.getKeyType()))) {
            append(canonical, "e", String.valueOf(jwk.getProperty(JsonWebKey.RSA_PUBLIC_EXP)));
            canonical.append(',');
            append(canonical, "kty", "RSA");
            canonical.append(',');
            append(canonical, "n", String.valueOf(jwk.getProperty(JsonWebKey.RSA_MODULUS)));
        } else if ("EC".equals(String.valueOf(jwk.getKeyType()))) {
            append(canonical, "crv", String.valueOf(jwk.getProperty(JsonWebKey.EC_CURVE)));
            canonical.append(',');
            append(canonical, "kty", "EC");
            canonical.append(',');
            append(canonical, "x", String.valueOf(jwk.getProperty(JsonWebKey.EC_X_COORDINATE)));
            canonical.append(',');
            append(canonical, "y", String.valueOf(jwk.getProperty(JsonWebKey.EC_Y_COORDINATE)));
        } else if ("OKP".equals(String.valueOf(jwk.getKeyType()))) {
            append(canonical, "crv", String.valueOf(jwk.getProperty("crv")));
            canonical.append(',');
            append(canonical, "kty", "OKP");
            canonical.append(',');
            append(canonical, "x", String.valueOf(jwk.getProperty("x")));
        } else {
            throw new DpopValidationException("unsupported key type for thumbprint");
        }
        canonical.append('}');
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private static void append(StringBuilder json, String name, String value) {
        json.append('"').append(name).append("\":\"").append(value).append('"');
    }

    /** RFC 9449: scheme + host + port + path, no query or fragment. */
    static String normalize(String uri) {
        try {
            java.net.URL url = new java.net.URL(uri);
            int port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
            return url.getProtocol() + "://" + url.getHost() + ":" + port + url.getPath();
        } catch (java.net.MalformedURLException ex) {
            return uri;
        }
    }

    private static PublicKey toPublicKey(JsonWebKey jwk) {
        try {
            PublicKey rsa = JwkUtils.toRSAPublicKey(jwk, false);
            if (rsa != null) {
                return rsa;
            }
        } catch (RuntimeException ignored) {
            // not RSA
        }
        try {
            PublicKey ec = JwkUtils.toECPublicKey(jwk);
            if (ec != null) {
                return ec;
            }
        } catch (RuntimeException ignored) {
            // not EC
        }
        throw new DpopValidationException("unsupported jwk key type");
    }

    private void evict(long now) {
        if (seenJti.size() < 1024) {
            return;
        }
        seenJti.entrySet().removeIf(entry -> now - entry.getValue() > freshnessSeconds * 2);
    }

    /** DPoP failure — callers map this to HTTP 401 with the DPoP-Nonce retry flow omitted. */
    public static final class DpopValidationException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public DpopValidationException(String message) {
            super(message);
        }
    }
}
