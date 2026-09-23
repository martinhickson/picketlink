package org.picketlink.auth.oauth.issuance;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
import org.apache.cxf.rs.security.jose.jws.JwsCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * Validates RFC 7523 {@code client_assertion} JWTs presented by REST clients at the token
 * endpoint, enabling fully automated (secret-free) client authentication with
 * {@code private_key_jwt}.
 *
 * <p>Enforced: asymmetric algorithms only (no {@code none}, no HMAC — prevents client-secret
 * confusion), {@code iss}/{@code sub} must equal the client id, audience must be this issuer,
 * lifetime window, unique {@code jti} (replay protection) and signature against the client's
 * registered JWKS.
 */
public final class ClientAssertionValidator {

    /** RFC 7523 §3: assertions should be short-lived; five minutes is the common ceiling. */
    public static final long DEFAULT_MAX_ASSERTION_LIFETIME_SECONDS = 300L;

    private static final Set<String> REJECTED_ALGORITHM_PREFIXES = Set.of("none", "HS");

    private final String expectedAudience;
    private final long maxAssertionLifetimeSeconds;
    private final Clock clock;
    private final ReplayCache replayCache;

    public ClientAssertionValidator(String expectedAudience, Clock clock) {
        this(expectedAudience, DEFAULT_MAX_ASSERTION_LIFETIME_SECONDS, clock,
                new ReplayCache(clock));
    }

    public ClientAssertionValidator(String expectedAudience, long maxAssertionLifetimeSeconds,
            Clock clock, ReplayCache replayCache) {
        this.expectedAudience = expectedAudience;
        this.maxAssertionLifetimeSeconds = maxAssertionLifetimeSeconds;
        this.clock = clock;
        this.replayCache = replayCache;
    }

    /** Reads the unverified {@code iss} claim so the caller can look up the registered client. */
    public String readIssuer(String clientAssertion) {
        try {
            JwsCompactConsumer consumer = new JwsCompactConsumer(clientAssertion);
            JwtClaims claims = readClaims(consumer);
            return claims.getIssuer();
        } catch (RuntimeException ex) {
            throw invalidClient("Malformed client_assertion");
        }
    }

    /**
     * Fully validates the assertion for the given registered client.
     *
     * @return the verified claims
     */
    public JwtClaims validate(String clientAssertion, RegisteredClient client) {
        JwsCompactConsumer consumer;
        try {
            consumer = new JwsCompactConsumer(clientAssertion);
        } catch (RuntimeException ex) {
            throw invalidClient("Malformed client_assertion");
        }

        SignatureAlgorithm algorithm = consumer.getJwsHeaders().getSignatureAlgorithm();
        if (algorithm == null || isRejectedAlgorithm(algorithm)) {
            throw invalidClient("client_assertion must be signed with an asymmetric algorithm");
        }

        if (!verifySignature(consumer, algorithm, client)) {
            throw invalidClient("Invalid client_assertion signature");
        }

        JwtClaims claims = readClaims(consumer);
        String clientId = client.getClientId();
        if (!clientId.equals(claims.getIssuer()) || !clientId.equals(claims.getSubject())) {
            throw invalidClient("client_assertion iss/sub must equal client_id");
        }
        if (!hasAudience(claims, expectedAudience)) {
            throw invalidClient("client_assertion audience mismatch");
        }

        long now = clock.instant().getEpochSecond();
        Long issuedAt = claims.getIssuedAt();
        Long expiry = claims.getExpiryTime();
        if (expiry == null || expiry <= now) {
            throw invalidClient("client_assertion has expired");
        }
        if (issuedAt == null || expiry - issuedAt > maxAssertionLifetimeSeconds) {
            throw invalidClient("client_assertion lifetime exceeds the allowed window");
        }
        Long notBefore = claims.getNotBefore();
        if (notBefore != null && notBefore > now) {
            throw invalidClient("client_assertion not yet valid");
        }

        String tokenId = claims.getTokenId();
        if (tokenId == null || tokenId.isBlank()) {
            throw invalidClient("client_assertion requires a jti");
        }
        if (!replayCache.checkAndStore(clientId + ":" + tokenId,
                Duration.ofSeconds(maxAssertionLifetimeSeconds))) {
            throw invalidClient("client_assertion has already been used");
        }
        return claims;
    }

    private boolean verifySignature(JwsCompactConsumer consumer, SignatureAlgorithm algorithm,
            RegisteredClient client) {
        String jwksJson = client.getJwks();
        if (jwksJson == null || jwksJson.isBlank()) {
            throw invalidClient("Client has no registered JWKS for private_key_jwt authentication");
        }
        JsonWebKeys jwks;
        try {
            jwks = JwkUtils.readJwkSet(jwksJson);
        } catch (RuntimeException ex) {
            throw invalidClient("Client JWKS is invalid");
        }
        String kid = consumer.getJwsHeaders().getKeyId();
        List<JsonWebKey> candidates = jwks.getKeys();
        if (candidates == null || candidates.isEmpty()) {
            throw invalidClient("Client JWKS contains no keys");
        }
        if (kid != null) {
            JsonWebKey jwk = jwks.getKey(kid);
            if (jwk == null) {
                return false;
            }
            return consumer.verifySignatureWith(toPublicKey(jwk), algorithm);
        }
        if (candidates.size() != 1) {
            throw invalidClient("client_assertion kid is required when the client JWKS has multiple keys");
        }
        return consumer.verifySignatureWith(toPublicKey(candidates.get(0)), algorithm);
    }

    private static PublicKey toPublicKey(JsonWebKey jwk) {
        try {
            PublicKey publicKey = JwkUtils.toRSAPublicKey(jwk, false);
            if (publicKey != null) {
                return publicKey;
            }
        } catch (RuntimeException ignored) {
            // not an RSA key
        }
        try {
            PublicKey ecKey = JwkUtils.toECPublicKey(jwk);
            if (ecKey != null) {
                return ecKey;
            }
        } catch (RuntimeException ignored) {
            // not an EC key
        }
        throw invalidClient("Client JWKS key type is not supported");
    }

    private static boolean isRejectedAlgorithm(SignatureAlgorithm algorithm) {
        String name = algorithm.getJwaName();
        if (name == null) {
            return true;
        }
        for (String prefix : REJECTED_ALGORITHM_PREFIXES) {
            if (name.regionMatches(true, 0, prefix, 0, prefix.length())) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasAudience(JwtClaims claims, String expected) {
        List<String> audiences = claims.getAudiences();
        if (audiences != null && audiences.contains(expected)) {
            return true;
        }
        return expected.equals(claims.getAudience());
    }

    private static JwtClaims readClaims(JwsCompactConsumer consumer) {
        return new JwtClaims(new JsonMapObjectReaderWriter().fromJson(consumer.getDecodedJwsPayload()));
    }

    private static OAuthException invalidClient(String description) {
        return new OAuthException(
                new OAuthErrorResponse(OAuthConstants.INVALID_CLIENT, description), 401);
    }
}
