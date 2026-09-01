package org.picketlink.auth.oauth.service;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.InMemoryClientRegistry;
import org.picketlink.auth.oauth.issuance.AudiencePinningRule;
import org.picketlink.auth.oauth.issuance.IssuancePolicyEngine;
import org.picketlink.auth.oauth.issuance.IssuanceRequest;
import org.picketlink.auth.oauth.issuance.JwtIssuanceManager;
import org.picketlink.auth.oauth.issuance.MaxTokenLifetimeRule;
import org.picketlink.auth.oauth.issuance.CxfJoseJwtSigningService;
import org.picketlink.auth.oauth.issuance.SecureSigningAlgorithmRule;
import org.picketlink.auth.oauth.issuance.SigningKey;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry;

class TokenLifecycleServiceTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String CLIENT_ID = "rest-client";
    private static final String CLIENT_SECRET = "the-secret";

    private JwtIssuanceManager manager;
    private InMemoryClientRegistry clientRegistry;
    private ClientCredentialsAuthenticator authenticator;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        manager = new JwtIssuanceManager(ISSUER,
                new CxfJoseJwtSigningService(ISSUER,
                        List.of(SigningKey.forKeyPair("key-1", keyPair, SignatureAlgorithm.RS256)),
                        "key-1"),
                new IssuancePolicyEngine(List.of(
                        new SecureSigningAlgorithmRule(java.util.Set.of("RS256")),
                        new MaxTokenLifetimeRule(600L),
                        new AudiencePinningRule())),
                new InMemoryAccessTokenRegistry(), null, "RS256", 300L);
        clientRegistry = new InMemoryClientRegistry();
        clientRegistry.register(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET).scope("read").build());
        authenticator = new ClientCredentialsAuthenticator(clientRegistry,
                new ConstantTimeClientSecretMatcher());
    }

    private TokenRequest authenticatedRequest() {
        String basic = "Basic " + Base64.getEncoder().encodeToString(
                (CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        return TokenRequest.builder()
                .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                .authorizationHeader(basic)
                .build();
    }

    private String issueToken() {
        return manager.issue(IssuanceRequest.forClient(
                        RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET).scope("read").build())
                .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                .scopes(java.util.Set.of("read"))
                .build()).getTokenValue();
    }

    @Test
    void introspectionShouldReportActiveForValidToken() {
        String token = issueToken();
        TokenIntrospectionService service = new TokenIntrospectionService(authenticator, manager);
        TokenRequest request = TokenRequest.builder()
                .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                .authorizationHeader(authenticatedRequest().getAuthorizationHeader())
                .formParameter(OAuthConstants.ACCESS_TOKEN, token)
                .build();
        String json = service.introspect(request);

        assertTrue(json.contains("\"active\":true"));
        assertTrue(json.contains("\"client_id\":\"rest-client\""));
        assertTrue(json.contains("\"scope\":\"read\""));
        assertTrue(json.contains("\"jti\""));
    }

    @Test
    void introspectionShouldReportInactiveAfterRevocation() {
        String token = issueToken();
        TokenRequest revokeRequest = TokenRequest.builder()
                .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                .authorizationHeader(authenticatedRequest().getAuthorizationHeader())
                .formParameter(OAuthConstants.ACCESS_TOKEN, token)
                .build();
        new TokenRevocationService(authenticator, manager).revoke(revokeRequest);

        TokenRequest introspectRequest = TokenRequest.builder()
                .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                .authorizationHeader(authenticatedRequest().getAuthorizationHeader())
                .formParameter(OAuthConstants.ACCESS_TOKEN, token)
                .build();
        String json = new TokenIntrospectionService(authenticator, manager).introspect(introspectRequest);
        assertTrue(json.contains("\"active\":false"));
    }

    @Test
    void introspectionShouldReportInactiveForGarbageToken() {
        TokenRequest request = TokenRequest.builder()
                .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                .authorizationHeader(authenticatedRequest().getAuthorizationHeader())
                .formParameter(OAuthConstants.ACCESS_TOKEN, "not-a-jwt")
                .build();
        String json = new TokenIntrospectionService(authenticator, manager).introspect(request);
        assertTrue(json.contains("\"active\":false"));
    }

    @Test
    void managedTokenServiceShouldIssueAndValidate() {
        JwtClientCredentialsTokenService service = new JwtClientCredentialsTokenService(
                authenticator, manager);
        var response = service.issueToken(authenticatedRequest());
        assertNotNull(response.getAccessToken());
        assertNotNull(service.validateToken(response.getAccessToken()));
    }
}
