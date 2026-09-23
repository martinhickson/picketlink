package org.picketlink.auth.oauth.issuance;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.Set;

import org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.jwt.JwtSigner;
import org.picketlink.auth.oauth.jwt.JwtValidationException;

/**
 * Signs and verifies issuance JWTs with a {@link JwtSigner}. A rotating signer keeps using
 * the key published by OIDC key rotation. The public half is that signer's JWKS document.
 */
public final class RsaJwtSigningService implements JwtSigningService {

    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

    private final String issuer;
    private final JwtSigner signer;
    private final Clock clock;

    public RsaJwtSigningService(String issuer, JwtSigner signer) {
        this(issuer, signer, Clock.systemUTC());
    }

    public RsaJwtSigningService(String issuer, JwtSigner signer, Clock clock) {
        this.issuer = issuer;
        this.signer = signer;
        this.clock = clock;
    }

    public JwtSigner getSigner() {
        return signer;
    }

    @Override
    public String sign(JwtClaims claims, String algorithm) {
        if (algorithm != null && !signer.algorithm().equals(algorithm)) {
            throw new JwtValidationException("Active key does not support algorithm " + algorithm);
        }
        String header = "{\"alg\":\"" + signer.algorithm() + "\",\"typ\":\"JWT\",\"kid\":\""
                + signer.keyId() + "\"}";
        String payload = new JsonMapObjectReaderWriter().toJson(claims);
        String content = URL.encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + "." + URL.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign(content.getBytes(StandardCharsets.UTF_8));
        return content + "." + URL.encodeToString(signature);
    }

    @Override
    public JwtClaims validate(String compactJwt, Set<String> acceptedAlgorithms) {
        return validate(compactJwt, acceptedAlgorithms, 0L);
    }

    @Override
    public JwtClaims validate(String compactJwt, Set<String> acceptedAlgorithms, long skewSeconds) {
        if (compactJwt == null || compactJwt.isBlank()) {
            throw new JwtValidationException("Missing bearer token");
        }
        String[] parts = compactJwt.split("\\.");
        if (parts.length != 3) {
            throw new JwtValidationException("Malformed JWT");
        }
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        if (!headerJson.contains("\"alg\":\"" + signer.algorithm() + "\"")) {
            throw new JwtValidationException("JWT algorithm is not accepted");
        }
        if (acceptedAlgorithms != null && !acceptedAlgorithms.isEmpty()
                && !acceptedAlgorithms.contains(signer.algorithm())) {
            throw new JwtValidationException("JWT algorithm " + signer.algorithm() + " is not accepted");
        }
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        byte[] content = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8);
        if (!signer.verify(content, signature)) {
            throw new JwtValidationException("Invalid JWT signature");
        }
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        JwtClaims claims = new JwtClaims(new JsonMapObjectReaderWriter().fromJson(payloadJson));
        if (!issuer.equals(claims.getIssuer())) {
            throw new JwtValidationException("Invalid JWT issuer");
        }
        Long expiry = claims.getExpiryTime();
        long now = clock.instant().getEpochSecond();
        if (expiry == null || expiry <= now - skewSeconds) {
            throw new JwtValidationException("JWT has expired");
        }
        return claims;
    }

    @Override
    public String publicJwksJson() {
        return signer.jwks();
    }

    @Override
    public String activeKeyId() {
        return signer.keyId();
    }
}
