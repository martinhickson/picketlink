package org.picketlink.auth.oauth.issuance;

import java.util.Set;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;

/**
 * Signs and verifies JWTs using the CXF JOSE implementation. Implementations are responsible
 * for key selection (including rotation) and for publishing the public keys as JWKS.
 */
public interface JwtSigningService {

    /** Signs the claims using the currently active key and the given JOSE algorithm name (e.g. RS256). */
    String sign(JwtClaims claims, String algorithm);

    /**
     * Verifies signature, issuer, expiry and not-before of the compact JWT. Rejects tokens signed
     * with an algorithm outside {@code acceptedAlgorithms} (JOSE algorithm confusion protection).
     *
     * @return the verified claims
     * @throws org.picketlink.auth.oauth.jwt.JwtValidationException if any check fails
     */
    JwtClaims validate(String compactJwt, Set<String> acceptedAlgorithms);

    /** JWKS JSON document containing the publishable (asymmetric) keys, including recently rotated ones. */
    String publicJwksJson();

    /**
     * As {@link #validate(String, Set)} with clock-skew leeway; implementations without
     * skew support fall back to exact time checks.
     */
    default JwtClaims validate(String compactJwt, Set<String> acceptedAlgorithms, long skewSeconds) {
        return validate(compactJwt, acceptedAlgorithms);
    }

    /** Key id of the key currently used for signing. */
    String activeKeyId();
}
