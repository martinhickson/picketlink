package org.picketlink.auth.oauth.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.jwt.JwtValidationException;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry;

class JwtIssuanceManagerTest {

    private static final String ISSUER = "https://auth.example.test";

    private static KeyPair rsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static CxfJoseJwtSigningService signingService(Clock clock) {
        return new CxfJoseJwtSigningService(ISSUER,
                List.of(SigningKey.forKeyPair("key-1", rsaKeyPair(), SignatureAlgorithm.RS256)),
                "key-1", clock);
    }

    private static JwtIssuanceManager manager(Clock clock, List<IssuanceRule> extraRules) {
        List<IssuanceRule> rules = new ArrayList<>(List.of(
                new SecureSigningAlgorithmRule(Set.of("RS256")),
                new MaxTokenLifetimeRule(600L),
                new AudiencePinningRule()));
        rules.addAll(extraRules);
        return new JwtIssuanceManager(ISSUER, signingService(clock),
                new IssuancePolicyEngine(rules), new InMemoryAccessTokenRegistry(),
                null, "RS256", 300L, clock);
    }

    private static RegisteredClient client() {
        return RegisteredClient.builder("rest-client", "secret")
                .scope("read")
                .build();
    }

    @Test
    void shouldIssuePolicyApprovedTokenWithExpectedClaims() {
        Clock clock = Clock.fixed(Instant.ofEpochSecond(10_000), ZoneOffset.UTC);
        JwtIssuanceManager manager = manager(clock, List.of());

        IssuedToken issued = manager.issue(IssuanceRequest.forClient(client())
                .grantType("client_credentials")
                .scopes(Set.of("read"))
                .audiences(Set.of("https://api.example.test"))
                .build());

        assertNotNull(issued.getTokenValue());
        JwtClaims claims = manager.validate(issued.getTokenValue());
        assertEquals("rest-client", claims.getSubject());
        assertEquals("rest-client", claims.getClaim(JwtIssuanceManager.CLAIM_CLIENT_ID));
        assertEquals("read", claims.getClaim(JwtIssuanceManager.CLAIM_SCOPE));
        assertEquals(List.of("https://api.example.test"), claims.getAudiences());
        assertEquals(10_000 + 300, claims.getExpiryTime());
        assertEquals(300L, issued.getLifetimeSeconds());
    }

    @Test
    void shouldClampLifetimeToPolicyMaximum() {
        Clock clock = Clock.fixed(Instant.ofEpochSecond(10_000), ZoneOffset.UTC);
        JwtIssuanceManager manager = manager(clock, List.of());

        IssuedToken issued = manager.issue(IssuanceRequest.forClient(client())
                .grantType("client_credentials")
                .requestedLifetimeSeconds(86_400L)
                .build());

        assertEquals(600L, issued.getLifetimeSeconds());
    }

    @Test
    void shouldClampLifetimeToStricterClientMaximum() {
        Clock clock = Clock.fixed(Instant.ofEpochSecond(10_000), ZoneOffset.UTC);
        JwtIssuanceManager manager = manager(clock, List.of());
        RegisteredClient restricted = RegisteredClient.builder("restricted", "secret")
                .maxTokenLifetimeSeconds(60L)
                .build();

        IssuedToken issued = manager.issue(IssuanceRequest.forClient(restricted)
                .grantType("client_credentials")
                .requestedLifetimeSeconds(600L)
                .build());

        assertEquals(60L, issued.getLifetimeSeconds());
    }

    @Test
    void shouldRejectDisallowedAudience() {
        JwtIssuanceManager manager = manager(Clock.systemUTC(), List.of());
        RegisteredClient pinned = RegisteredClient.builder("pinned", "secret")
                .allowedAudiences(Set.of("https://api-one.example.test"))
                .build();

        IssuancePolicyException ex = assertThrows(IssuancePolicyException.class,
                () -> manager.issue(IssuanceRequest.forClient(pinned)
                        .grantType("client_credentials")
                        .audiences(Set.of("https://api-two.example.test"))
                        .build()));
        assertTrue(ex.getMessage().contains("not allowed"));
    }

    @Test
    void shouldRejectWhenPolicyAllowsNoAlgorithmForManager() {
        JwtIssuanceManager restrictive = new JwtIssuanceManager(ISSUER,
                signingService(Clock.systemUTC()),
                new IssuancePolicyEngine(List.of(new SecureSigningAlgorithmRule(Set.of("ES256")))),
                new InMemoryAccessTokenRegistry(), null, "RS256", 300L, Clock.systemUTC());
        assertThrows(IssuancePolicyException.class,
                () -> restrictive.issue(IssuanceRequest.forClient(client())
                        .grantType("client_credentials")
                        .build()));
    }

    @Test
    void secureSigningAlgorithmRuleShouldRejectNoneAndUnknown() {
        SecureSigningAlgorithmRule rule = new SecureSigningAlgorithmRule(Set.of("RS256", "ES256"));
        IssuanceContext none = new IssuanceContext(client(), "client_credentials",
                Set.of(), Set.of(), 300L, "none");
        assertThrows(IssuancePolicyException.class, () -> rule.enforce(none));

        IssuanceContext unknown = new IssuanceContext(client(), "client_credentials",
                Set.of(), Set.of(), 300L, "HS256");
        assertThrows(IssuancePolicyException.class, () -> rule.enforce(unknown));

        IssuanceContext ok = new IssuanceContext(client(), "client_credentials",
                Set.of(), Set.of(), 300L, "RS256");
        rule.enforce(ok);
    }

    @Test
    void revokedTokenShouldFailValidation() {
        JwtIssuanceManager manager = manager(Clock.systemUTC(), List.of());
        IssuedToken issued = manager.issue(IssuanceRequest.forClient(client())
                .grantType("client_credentials")
                .build());

        assertNotNull(manager.validate(issued.getTokenValue()));
        assertTrue(manager.revoke(issued.getTokenValue(), "rest-client"));
        assertThrows(JwtValidationException.class, () -> manager.validate(issued.getTokenValue()));
    }

    @Test
    void revokeShouldOnlyAffectOwnTokens() {
        JwtIssuanceManager manager = manager(Clock.systemUTC(), List.of());
        IssuedToken issued = manager.issue(IssuanceRequest.forClient(client())
                .grantType("client_credentials")
                .build());

        assertEquals(false, manager.revoke(issued.getTokenValue(), "other-client"));
        assertNotNull(manager.validate(issued.getTokenValue()));
    }

    @Test
    void auditListenerShouldSeeIssuedAndRejectedEvents() {
        List<IssuanceAuditEvent> events = new ArrayList<>();
        JwtIssuanceManager manager = new JwtIssuanceManager(ISSUER, signingService(Clock.systemUTC()),
                new IssuancePolicyEngine(List.of(new AudiencePinningRule())),
                new InMemoryAccessTokenRegistry(), events::add, "RS256", 300L, Clock.systemUTC());

        manager.issue(IssuanceRequest.forClient(client()).grantType("client_credentials").build());
        RegisteredClient pinned = RegisteredClient.builder("pinned", "secret")
                .allowedAudiences(Set.of("https://api-one.example.test"))
                .build();
        assertThrows(IssuancePolicyException.class,
                () -> manager.issue(IssuanceRequest.forClient(pinned)
                        .grantType("client_credentials")
                        .audiences(Set.of("https://api-two.example.test"))
                        .build()));

        assertEquals(2, events.size());
        assertEquals(IssuanceAuditEvent.Outcome.ISSUED, events.get(0).getOutcome());
        assertEquals(IssuanceAuditEvent.Outcome.REJECTED, events.get(1).getOutcome());
        assertEquals("rest-client", events.get(0).getClientId());
        assertNotNull(events.get(1).getReason());
    }
}
