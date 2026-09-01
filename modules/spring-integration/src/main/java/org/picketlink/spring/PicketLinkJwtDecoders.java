package org.picketlink.spring;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;

import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Spring Security resource-server integration for PicketLink-issued JWTs.
 *
 * <p>Usage in a Spring Boot application (no Spring dependency is forced on the issuer side —
 * the adapter only needs the issuer's public JWKS):
 *
 * <pre>{@code
 * @Bean
 * JwtDecoder jwtDecoder() {
 *     return PicketLinkJwtDecoders.fromIssuer("https://auth.corp.example");
 * }
 *
 * @Bean
 * SecurityFilterChain apiSecurity(HttpSecurity http, JwtDecoder decoder) throws Exception {
 *     http.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
 *         .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt
 *             .decoder(decoder)
 *             .jwtAuthenticationConverter(new PicketLinkJwtAuthenticationConverter())));
 *     return http.build();
 * }
 * }</pre>
 */
public final class PicketLinkJwtDecoders {

    /** Default JWKS path published by the PicketLink issuance layer. */
    public static final String JWKS_PATH = "/.well-known/jwks.json";

    private PicketLinkJwtDecoders() {
    }

    /**
     * Decoder for a PicketLink issuer: resolves {@code <issuer>/.well-known/jwks.json} with
     * Nimbus caching/rotation support, requires the exact issuer claim, allows RS256/ES256
     * (PicketLink's policy-approved algorithms) and defaults (exp, nbf with 60s clock skew).
     */
    public static JwtDecoder fromIssuer(String issuer) {
        return fromJwksUri(issuer + JWKS_PATH, issuer);
    }

    /** As {@link #fromIssuer(String)} but with an explicit JWKS URI. */
    public static JwtDecoder fromJwksUri(String jwksUri, String expectedIssuer) {
        NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder builder = NimbusJwtDecoder.withJwkSetUri(jwksUri);
        builder.jwsAlgorithms(algorithms -> {
            algorithms.add(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256);
            algorithms.add(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.ES256);
        });
        NimbusJwtDecoder decoder = builder.build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(expectedIssuer));
        return decoder;
    }

    /**
     * Decoder over a static JWKS document (useful for tests or pinned deployments): uses the
     * first RSA key in the document. Key rotation requires a restart — prefer
     * {@link #fromIssuer(String)}, which refreshes keys automatically.
     */
    public static JwtDecoder fromStaticJwks(String jwksJson, String expectedIssuer) {
        JWKSet jwkSet;
        try {
            jwkSet = JWKSet.parse(jwksJson);
        } catch (ParseException ex) {
            throw new IllegalArgumentException("Invalid JWKS document", ex);
        }
        java.security.interfaces.RSAPublicKey publicKey = null;
        for (com.nimbusds.jose.jwk.JWK jwk : jwkSet.getKeys()) {
            if (jwk instanceof com.nimbusds.jose.jwk.RSAKey) {
                try {
                    publicKey = ((com.nimbusds.jose.jwk.RSAKey) jwk).toRSAPublicKey();
                } catch (com.nimbusds.jose.JOSEException ex) {
                    throw new IllegalArgumentException("Unable to read RSA public key from JWKS", ex);
                }
                break;
            }
        }
        if (publicKey == null) {
            throw new IllegalArgumentException("JWKS document contains no RSA key");
        }
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(expectedIssuer));
        return decoder;
    }

    /** Convenience for fetching a JWKS document (mirrors what the issuer publishes). */
    public static String fetchJwks(String jwksUri) {
        try {
            return new String(new URL(jwksUri).openStream().readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to fetch JWKS from " + jwksUri, ex);
        }
    }

    /** The PicketLink {@code scope} claim is a space-separated string, like {@code scp}. */
    public static String[] scopes(JWTClaimsSet claims) {
        String scope = claims.getClaim("scope") == null ? null : String.valueOf(claims.getClaim("scope"));
        if (scope == null || scope.isBlank()) {
            return new String[0];
        }
        return scope.trim().split("\\s+");
    }
}
