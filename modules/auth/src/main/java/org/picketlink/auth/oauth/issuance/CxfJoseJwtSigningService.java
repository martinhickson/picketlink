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
        if (algorithm != null && !key.getAlgorithm().name().equals(algorithm)) {
            throw new JwtValidationException("Active key does not support algorithm " + algorithm);
        }
        JwsHeaders headers = new JwsHeaders();
        headers.setAlgorithm(key.getAlgorithm().name());
        headers.setKeyId(key.getKeyId());
        return new JwsJwtCompactProducer(headers, claims).signWith(key.getSignatureProvider());
    }

    @Override
    public JwtClaims validate(String compactJwt, Set<String> acceptedAlgorithms) {
        if (compactJwt == null || compactJwt.isBlank()) {
            throw new JwtValidationException("Missing bearer token");
        }
        JwsCompactConsumer consumer;
        try {
            consumer = new JwsCompactConsumer(compactJwt);
        } catch (RuntimeException ex) {
            throw new JwtValidationException("Malformed JWT");
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

        JwtClaims claims = readClaims(consumer);
        long now = clock.instant().getEpochSecond();
        if (!issuer.equals(claims.getIssuer())) {
            throw new JwtValidationException("Invalid JWT issuer");
        }
        Long expiry = claims.getExpiryTime();
        if (expiry == null || expiry <= now) {
            throw new JwtValidationException("JWT has expired");
        }
        Long notBefore = claims.getNotBefore();
        if (notBefore != null && notBefore > now) {
            throw new JwtValidationException("JWT not yet valid");
        }
        return claims;
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
            jwk.setProperty(JsonWebKey.EC_CURVE, curve(ec));
            jwk.setProperty(JsonWebKey.EC_X_COORDINATE, encode(ec.getW().getAffineX()));
            jwk.setProperty(JsonWebKey.EC_Y_COORDINATE, encode(ec.getW().getAffineY()));
            return jwk;
        }
        return null;
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

    private static String encode(BigInteger value) {
        return URL_ENCODER.encodeToString(value.toByteArray());
    }

    @Override
    public String activeKeyId() {
        return activeKeyId;
    }
}
