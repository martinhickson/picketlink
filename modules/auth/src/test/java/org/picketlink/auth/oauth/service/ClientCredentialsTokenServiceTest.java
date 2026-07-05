package org.picketlink.auth.oauth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.InMemoryClientRegistry;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.token.AccessTokenGenerator;
import org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry;

class ClientCredentialsTokenServiceTest {

    private ClientCredentialsTokenService tokenService;
    private InMemoryAccessTokenRegistry tokenRegistry;

    @BeforeEach
    void setUp() {
        InMemoryClientRegistry clientRegistry = new InMemoryClientRegistry();
        clientRegistry.register(RegisteredClient.builder("service-a", "s3cr3t")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                .build());
        tokenRegistry = new InMemoryAccessTokenRegistry();
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        tokenService = new ClientCredentialsTokenService(
                new ClientCredentialsAuthenticator(clientRegistry, new ConstantTimeClientSecretMatcher()),
                new AccessTokenGenerator(16),
                tokenRegistry,
                clock);
        tokenService.setAccessTokenLifetimeSeconds(120L);
    }

    @Test
    void issuesBearerTokenForValidClientCredentialsRequest() {
        TokenRequest request = TokenRequest.builder()
                .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                .scope("api.read")
                .formParameter(OAuthConstants.CLIENT_ID, "service-a")
                .formParameter(OAuthConstants.CLIENT_SECRET, "s3cr3t")
                .build();

        TokenResponse response = tokenService.issueToken(request);

        assertEquals(OAuthConstants.BEARER_TOKEN_TYPE, response.getTokenType());
        assertEquals(120L, response.getExpiresIn());
        assertEquals("api.read", response.getScope());
        assertNotNull(response.getAccessToken());
        assertTrue(tokenRegistry.findByTokenValue(response.getAccessToken()).isPresent());
    }

    @Test
    void rejectsUnsupportedGrantType() {
        TokenRequest request = TokenRequest.builder()
                .grantType("authorization_code")
                .formParameter(OAuthConstants.CLIENT_ID, "service-a")
                .formParameter(OAuthConstants.CLIENT_SECRET, "s3cr3t")
                .build();

        OAuthException ex = assertThrows(OAuthException.class, () -> tokenService.issueToken(request));
        assertEquals(OAuthConstants.UNSUPPORTED_GRANT_TYPE, ex.getError().getError());
    }

    @Test
    void acceptsBasicAuthentication() {
        String basic = "Basic "
                + Base64.getEncoder().encodeToString("service-a:s3cr3t".getBytes(StandardCharsets.UTF_8));
        RegisteredClient basicClient = RegisteredClient.builder("service-a", "s3cr3t")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build();
        InMemoryClientRegistry clientRegistry = new InMemoryClientRegistry();
        clientRegistry.register(basicClient);
        ClientCredentialsTokenService basicService = new ClientCredentialsTokenService(
                new ClientCredentialsAuthenticator(clientRegistry, new ConstantTimeClientSecretMatcher()),
                new AccessTokenGenerator(16),
                tokenRegistry);
        TokenRequest request = TokenRequest.builder()
                .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                .authorizationHeader(basic)
                .build();

        TokenResponse response = basicService.issueToken(request);

        assertNotNull(response.getAccessToken());
    }
}
