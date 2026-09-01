package org.picketlink.auth.oauth.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.jwt.JwtValidationException;

/** The developer-ergonomics contract: correct JWTs in five lines, every algorithm family. */
class PicketLinkJwtTest {

    @Test
    void shouldIssueAndValidateInFiveLinesWithRs256() {
        PicketLinkJwt jwt = PicketLinkJwt.issuer("https://auth.example").rs256().build();

        String token = jwt.issue("user-42", Set.of("read"));
        JwtClaims claims = jwt.validate(token);

        assertEquals("https://auth.example", claims.getIssuer());
        assertEquals("user-42", claims.getSubject());
        assertEquals("read", claims.getClaim(JwtIssuanceManager.CLAIM_SCOPE));
    }

    @Test
    void shouldSupportEd25519EndToEnd() {
        PicketLinkJwt jwt = PicketLinkJwt.issuer("https://auth.example").ed25519().build();

        String token = jwt.issue("user-42", Set.of("read"));
        assertNotNull(token.split("\\.")[2]);

        JwtClaims claims = jwt.validate(token);
        assertEquals("user-42", claims.getSubject());

        // EdDSA tokens are rejected by an RS256-only allow-list (algorithm confusion guard)
        PicketLinkJwt rsaOnly = PicketLinkJwt.issuer("https://auth.example").rs256().build();
        assertThrows(JwtValidationException.class, () -> rsaOnly.validate(token));
    }

    @Test
    void shouldSupportEs256() {
        PicketLinkJwt jwt = PicketLinkJwt.issuer("https://auth.example").es256().build();
        JwtClaims claims = jwt.validate(jwt.issue("user-42", Set.of("read")));
        assertEquals("user-42", claims.getSubject());
    }

    @Test
    void jwksShouldPublishOkpForEd25519() {
        PicketLinkJwt jwt = PicketLinkJwt.issuer("https://auth.example").ed25519().build();
        jwt.issue("warm-up", Set.of()); // ensure the key exists
        String jwks = jwt.jwks();
        assertTrue(jwks.contains("\"kty\":\"OKP\""));
        assertTrue(jwks.contains("\"crv\":\"Ed25519\""));
        assertTrue(jwks.contains("\"x\""));
    }

    @Test
    void rotationShouldKeepOldTokensValidAndPublishBothKeys() throws Exception {
        PicketLinkJwt jwt = PicketLinkJwt.issuer("https://auth.example").rs256().build();
        String oldToken = jwt.issue("user-42", Set.of("read"));

        String newKeyId = jwt.rotate();
        assertNotEquals("key-1", newKeyId);

        // overlap window: token signed with the retired key still validates
        assertEquals("user-42", jwt.validate(oldToken).getSubject());
        // and both keys are published for resource servers
        assertTrue(jwt.jwks().contains("key-1"));
        assertTrue(jwt.jwks().contains(newKeyId));
    }

    @Test
    void requirementsShouldEnforceAudienceScopeAndSubject() {
        PicketLinkJwt jwt = PicketLinkJwt.issuer("https://auth.example")
                .rs256()
                .audience("https://api.example")
                .build();
        String token = jwt.issue("user-42", Set.of("read", "write"));

        // all satisfied
        jwt.validate(token, JwtRequirements.requireAudience("https://api.example")
                .scope("read", "write")
                .subject("user-42"));

        assertThrows(JwtValidationException.class,
                () -> jwt.validate(token, JwtRequirements.requireAudience("https://other.api")));
        assertThrows(JwtValidationException.class,
                () -> jwt.validate(token, JwtRequirements.requireScope("admin")));
        assertThrows(JwtValidationException.class,
                () -> jwt.validate(token, JwtRequirements.requireSubject("someone-else")));
    }

    @Test
    void clockSkewShouldForgiveSmallDrift() throws Exception {
        // deterministic clocks: issue at T, validate at T+110 with a 100s token
        java.time.Clock issueClock = java.time.Clock.fixed(
                java.time.Instant.ofEpochSecond(10_000), java.time.ZoneOffset.UTC);
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        CxfJoseJwtSigningService service = new CxfJoseJwtSigningService("https://auth.example",
                java.util.List.of(SigningKey.forKeyPair("key-1", generator.generateKeyPair(),
                        org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm.RS256)),
                "key-1", issueClock);
        JwtIssuanceManager manager = new JwtIssuanceManager("https://auth.example", service,
                new IssuancePolicyEngine(new SecureSigningAlgorithmRule(Set.of("RS256")),
                        new MaxTokenLifetimeRule(600L)),
                null, null, "RS256", 100L, issueClock);
        org.picketlink.auth.oauth.model.RegisteredClient client =
                org.picketlink.auth.oauth.model.RegisteredClient.builder("c", null)
                        .tokenEndpointAuthMethod(
                                org.picketlink.auth.oauth.model.TokenEndpointAuthMethod.PRIVATE_KEY_JWT)
                        .jwks("{\"keys\":[]}")
                        .build();
        String token = manager.issue(IssuanceRequest.forClient(client)
                .scopes(Set.of("read")).build()).getTokenValue();

        // validator running 10s past expiry: exact clock rejects, 30s skew accepts
        java.time.Clock lateClock = java.time.Clock.fixed(
                java.time.Instant.ofEpochSecond(10_110), java.time.ZoneOffset.UTC);
        ((org.picketlink.auth.oauth.issuance.CxfJoseJwtSigningService)
                manager.getSigningService()).validate(token, Set.of("RS256"), 0L); // sanity: still fine at T
        assertThrows(JwtValidationException.class,
                () -> validateAt(manager, token, lateClock, 0L));
        assertNotNull(validateAt(manager, token, lateClock, 30L));
    }

    private static JwtClaims validateAt(JwtIssuanceManager manager, String token,
            java.time.Clock clock, long skew) {
        CxfJoseJwtSigningService service = (CxfJoseJwtSigningService) manager.getSigningService();
        return service.validateAtClock(token, Set.of("RS256"), skew, clock);
    }

    @Test
    void revocationShouldInvalidateIssuedTokens() {
        PicketLinkJwt jwt = PicketLinkJwt.issuer("https://auth.example").rs256().build();
        String token = jwt.issue("user-42", Set.of("read"));
        assertNotNull(jwt.validate(token));
        assertTrue(jwt.revoke(token));
        assertThrows(JwtValidationException.class, () -> jwt.validate(token));
    }
}
