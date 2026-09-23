package org.picketlink.auth.oauth.issuance;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
import org.apache.cxf.rs.security.jose.jwk.KeyType;
import org.apache.cxf.rs.security.jose.jwk.PublicKeyUse;
import org.apache.cxf.rs.security.jose.jws.JwsCompactConsumer;
import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.jwt.JwtValidationException;

/**
 * {@link JwtSigningService} built on the CXF JOSE stack. Keeps every registered {@link SigningKey}
 * available for verification so recently rotated keys keep validating until the last token issued
 * with them expires; only the active key signs new tokens.
 */
public final class CxfJoseJwtSigningService implements JwtSigningService {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final String issuer;
    private final Map<String, SigningKey> keysById = new LinkedHashMap<>();
    private final Clock clock;
    private volatile String activeKeyId;

    public CxfJoseJwtSigningService(String issuer, List<SigningKey> keys, String activeKeyId) {
        this(issuer, keys, activeKeyId, Clock.systemUTC());
    }

    public CxfJoseJwtSigningService(String issuer, List<SigningKey> keys, String activeKeyId, Clock clock) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("At least one signing key is required");
        }
        for (SigningKey key : keys) {
            this.keysById.put(key.getKeyId(), key);
        }
        setActiveKeyId(activeKeyId);
    }

    /** Switches the signing key without dropping previously registered keys (rotation overlap window). */
    public void setActiveKeyId(String keyId) {
        if (keyId == null || !keysById.containsKey(keyId)) {
            throw new IllegalArgumentException("Unknown signing key: " + keyId);
        }
        this.activeKeyId = keyId;
    }

    /** Registers an additional verification/signing key, e.g. one produced by a rotation. */
    public void addKey(SigningKey key) {
        Objects.requireNonNull(key, "key");
        synchronized (keysById) {
            keysById.put(key.getKeyId(), key);
        }
    }

    public void removeKey(String keyId) {
        synchronized (keysById) {
            keysById.remove(keyId);
        }
    }

    @Override
    public String sign(JwtClaims claims, String algorithm) {
        SigningKey key = keysById.get(activeKeyId);
        if (key == null) {
            throw new IllegalStateException("No active signing key");
        }
        if (key.isEd25519()) {
            if (algorithm != null && !"EdDSA".equals(algorithm)) {
                throw new JwtValidationException("Active key does not support algorithm " + algorithm);
            }
            return signEd25519(key, claims);
        }
        if (algorithm != null && !key.getAlgorithm().name().equals(algorithm)) {
            throw new JwtValidationException("Active key does not support algorithm " + algorithm);
        }
        JwsHeaders headers = new JwsHeaders();
        headers.setAlgorithm(key.getAlgorithm().name());
        headers.setKeyId(key.getKeyId());
        return new JwsJwtCompactProducer(headers, claims).signWith(key.getSignatureProvider());
    }

    /** Ed25519 JWS compact signing via plain JCA (CXF 4.x has no EdDSA enum). */
    private static String signEd25519(SigningKey key, JwtClaims claims) {
        try {
            String header = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\""
                    + (key.getKeyId() == null ? "" : ",\"kid\":\"" + key.getKeyId() + "\"")
                    + "}";
            String payload = new org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter()
                    .toJson(claims);
            String signingContent = URL_ENCODER.encodeToString(header.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    + "." + URL_ENCODER.encodeToString(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            java.security.Signature signature = java.security.Signature.getInstance("Ed25519");
            signature.initSign(key.getPrivateKey());
            signature.update(signingContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return signingContent + "." + URL_ENCODER.encodeToString(signature.sign());
        } catch (java.security.GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to sign Ed25519 JWT", ex);
        }
    }

    @Override
    public JwtClaims validate(String compactJwt, Set<String> acceptedAlgorithms) {
        return validate(compactJwt, acceptedAlgorithms, 0L);
    }

    /**
     * As {@link #validate(String, Set)} with clock-skew leeway (seconds): tokens are
     * considered valid up to {@code skewSeconds} past expiry / before not-before, absorbing
     * small clock drift between issuer and validator.
     */
    @Override
    public JwtClaims validate(String compactJwt, Set<String> acceptedAlgorithms, long skewSeconds) {
        if (compactJwt == null || compactJwt.isBlank()) {
            throw new JwtValidationException("Missing bearer token");
        }
        JwsCompactConsumer consumer;
        try {
            consumer = new JwsCompactConsumer(compactJwt);
        } catch (RuntimeException ex) {
            throw new JwtValidationException("Malformed JWT");
        }
        String algorithmName = consumer.getJwsHeaders().getAlgorithm();
        if ("EdDSA".equals(algorithmName)) {
            if (acceptedAlgorithms != null && !acceptedAlgorithms.isEmpty()
                    && !acceptedAlgorithms.contains("EdDSA")) {
                throw new JwtValidationException("JWT algorithm EdDSA is not accepted");
            }
            if (!verifyEd25519(consumer)) {
                throw new JwtValidationException("Invalid JWT signature");
            }
            return checkClaims(consumer, skewSeconds, clock);
        }
        SignatureAlgorithm algorithm = consumer.getJwsHeaders().getSignatureAlgorithm();
        if (algorithm == null || SignatureAlgorithm.NONE == algorithm) {
            throw new JwtValidationException("Unsigned JWTs are not accepted");
        }
        if (acceptedAlgorithms != null && !acceptedAlgorithms.isEmpty()
                && !acceptedAlgorithms.contains(algorithm.name())) {
            throw new JwtValidationException("JWT algorithm " + algorithm + " is not accepted");
        }
        if (!verifySignature(consumer, algorithm)) {
            throw new JwtValidationException("Invalid JWT signature");
        }
        return checkClaims(consumer, skewSeconds, clock);
    }

    private JwtClaims checkClaims(JwsCompactConsumer consumer, long skewSeconds, Clock claimsClock) {
        JwtClaims claims = readClaims(consumer);
        long now = claimsClock.instant().getEpochSecond();
        if (!issuer.equals(claims.getIssuer())) {
            throw new JwtValidationException("Invalid JWT issuer");
        }
        Long expiry = claims.getExpiryTime();
        if (expiry == null || expiry <= now - skewSeconds) {
            throw new JwtValidationException("JWT has expired");
        }
        Long notBefore = claims.getNotBefore();
        if (notBefore != null && notBefore > now + skewSeconds) {
            throw new JwtValidationException("JWT not yet valid");
        }
        return claims;
    }

    /** Test support: validates with an explicit validator clock (clock-drift scenarios). */
    JwtClaims validateAtClock(String compactJwt, Set<String> acceptedAlgorithms, long skewSeconds,
            Clock claimsClock) {
        JwsCompactConsumer consumer = new JwsCompactConsumer(compactJwt);
        String algorithmName = consumer.getJwsHeaders().getAlgorithm();
        if ("EdDSA".equals(algorithmName)) {
            if (!verifyEd25519(consumer)) {
                throw new JwtValidationException("Invalid JWT signature");
            }
        } else if (!verifySignature(consumer, consumer.getJwsHeaders().getSignatureAlgorithm())) {
            throw new JwtValidationException("Invalid JWT signature");
        }
        return checkClaims(consumer, skewSeconds, claimsClock);
    }

    /** Ed25519 verification via plain JCA against every registered Ed key (kid match first). */
    private boolean verifyEd25519(JwsCompactConsumer consumer) {
        String keyId = consumer.getJwsHeaders().getKeyId();
        List<SigningKey> candidates = new ArrayList<>();
        synchronized (keysById) {
            for (SigningKey key : keysById.values()) {
                if (key.isEd25519() && (keyId == null || keyId.equals(key.getKeyId()))) {
                    candidates.add(key);
                }
            }
        }
        byte[] content = consumer.getUnsignedEncodedSequence()
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] signatureBytes = java.util.Base64.getUrlDecoder()
                .decode(consumer.getEncodedSignature());
        for (SigningKey key : candidates) {
            try {
                java.security.Signature verifier = java.security.Signature.getInstance("Ed25519");
                verifier.initVerify(key.getPublicKey());
                verifier.update(content);
                if (verifier.verify(signatureBytes)) {
                    return true;
                }
            } catch (java.security.GeneralSecurityException ex) {
                // try the next candidate key
            }
        }
        return false;
    }

    private boolean verifySignature(JwsCompactConsumer consumer, SignatureAlgorithm algorithm) {
        String keyId = consumer.getJwsHeaders().getKeyId();
        SigningKey key = keyId != null ? keysById.get(keyId) : null;
        if (key == null) {
            // No kid or unknown kid: only fall back to a single key to prevent cross-key confusion.
            List<SigningKey> candidates;
            synchronized (keysById) {
                candidates = new ArrayList<>(keysById.values());
            }
            if (keyId != null || candidates.size() != 1) {
                return false;
            }
            key = candidates.get(0);
        }
        if (key.getPublicKey() != null) {
            return consumer.verifySignatureWith(key.getPublicKey(), algorithm);
        }
        byte[] secret = key.getSecret();
        return secret != null && consumer.verifySignatureWith(secret, algorithm);
    }

    private static JwtClaims readClaims(JwsCompactConsumer consumer) {
        try {
            Map<String, Object> claimMap = new JsonMapObjectReaderWriter()
                    .fromJson(consumer.getDecodedJwsPayload());
            if (claimMap == null) {
                throw new JwtValidationException("Empty JWT payload");
            }
            return new JwtClaims(claimMap);
        } catch (JwtValidationException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new JwtValidationException("Malformed JWT payload");
        }
    }

    @Override
    public String publicJwksJson() {
        List<JsonWebKey> jwks = new ArrayList<>();
        synchronized (keysById) {
            for (SigningKey key : keysById.values()) {
                JsonWebKey jwk = toPublicJwk(key);
                if (jwk != null) {
                    jwks.add(jwk);
                }
            }
        }
        return JwkUtils.jwkSetToJson(new JsonWebKeys(jwks));
    }

    private static JsonWebKey toPublicJwk(SigningKey key) {
        if (!key.isPublishable()) {
            return null;
        }
        if (key.getPublicKey() instanceof RSAPublicKey) {
            RSAPublicKey rsa = (RSAPublicKey) key.getPublicKey();
            JsonWebKey jwk = new JsonWebKey();
            jwk.setKeyType(KeyType.RSA);
            jwk.setKeyId(key.getKeyId());
            jwk.setPublicKeyUse(PublicKeyUse.SIGN);
            jwk.setProperty(JsonWebKey.RSA_MODULUS, encode(rsa.getModulus()));
            jwk.setProperty(JsonWebKey.RSA_PUBLIC_EXP, encode(rsa.getPublicExponent()));
            return jwk;
        }
        if (key.getPublicKey() instanceof ECPublicKey) {
            ECPublicKey ec = (ECPublicKey) key.getPublicKey();
            JsonWebKey jwk = new JsonWebKey();
            jwk.setKeyType(KeyType.EC);
            jwk.setKeyId(key.getKeyId());
            jwk.setPublicKeyUse(PublicKeyUse.SIGN);
            int octets = fieldOctets(ec);
            jwk.setProperty(JsonWebKey.EC_CURVE, curve(ec));
            jwk.setProperty(JsonWebKey.EC_X_COORDINATE, encodeFixed(ec.getW().getAffineX(), octets));
            jwk.setProperty(JsonWebKey.EC_Y_COORDINATE, encodeFixed(ec.getW().getAffineY(), octets));
            return jwk;
        }
        if (key.getPublicKey() instanceof java.security.interfaces.EdECPublicKey) {
            // OKP/Ed25519 per RFC 8037 — modern JVMs (15+) generate these natively; CXF 4.x
            // has no OKP constants, so the JWK is written with plain property names
            java.security.interfaces.EdECPublicKey ed = (java.security.interfaces.EdECPublicKey) key.getPublicKey();
            byte[] raw = rawEd25519(ed);
            if (raw == null) {
                return null;
            }
            JsonWebKey jwk = new JsonWebKey();
            jwk.setProperty("kty", "OKP");
            jwk.setKeyId(key.getKeyId());
            jwk.setPublicKeyUse(PublicKeyUse.SIGN);
            jwk.setProperty("crv", "Ed25519");
            jwk.setProperty("x", Base64.getUrlEncoder().withoutPadding().encodeToString(raw));
            return jwk;
        }
        return null;
    }

    /** Raw 32-byte Ed25519 public key encoding for the JWK {@code x} coordinate. */
    private static byte[] rawEd25519(java.security.interfaces.EdECPublicKey key) {
        try {
            java.security.KeyFactory factory = java.security.KeyFactory.getInstance("Ed25519");
            java.security.spec.EdECPublicKeySpec spec = factory.getKeySpec(key,
                    java.security.spec.EdECPublicKeySpec.class);
            java.security.spec.EdECPoint point = spec.getPoint();
            // little-endian encoding per RFC 8032: y with sign bit in the top bit of byte 31
            byte[] raw = new byte[32];
            byte[] y = point.getY().toByteArray(); // big-endian, possibly 33 bytes with sign
            for (int i = 0; i < 32 && i < y.length; i++) {
                raw[i] = y[y.length - 1 - i];
            }
            if (point.isXOdd()) {
                raw[31] |= (byte) 0x80;
            }
            return raw;
        } catch (java.security.GeneralSecurityException ex) {
            return null;
        }
    }

    private static String curve(ECPublicKey ec) {
        int bits = ec.getParams().getOrder().bitLength();
        if (bits <= 256) {
            return JsonWebKey.EC_CURVE_P256;
        }
        if (bits <= 384) {
            return JsonWebKey.EC_CURVE_P384;
        }
        return JsonWebKey.EC_CURVE_P521;
    }

    /**
     * RFC 7518: the octet sequence is the minimum big-endian length, so the sign byte
     * {@link BigInteger#toByteArray()} inserts is not part of {@code n} or {@code e}.
     */
    private static String encode(BigInteger value) {
        return URL_ENCODER.encodeToString(unsigned(value));
    }

    /** EC coordinates are the full field width, left-padded with zeros (RFC 7518). */
    private static String encodeFixed(BigInteger value, int octets) {
        byte[] raw = unsigned(value);
        if (raw.length > octets) {
            throw new IllegalArgumentException("integer does not fit in " + octets + " octets");
        }
        if (raw.length < octets) {
            byte[] padded = new byte[octets];
            System.arraycopy(raw, 0, padded, octets - raw.length, raw.length);
            raw = padded;
        }
        return URL_ENCODER.encodeToString(raw);
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private static int fieldOctets(ECPublicKey ec) {
        int bits = ec.getParams().getCurve().getField().getFieldSize();
        return (bits + 7) / 8;
    }

    @Override
    public String activeKeyId() {
        return activeKeyId;
    }
}
