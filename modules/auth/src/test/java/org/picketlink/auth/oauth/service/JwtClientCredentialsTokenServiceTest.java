package org.picketlink.auth.oauth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.InMemoryClientRegistry;
import org.picketlink.auth.oauth.jwt.JwtAccessTokenIssuer;
import org.picketlink.auth.oauth.jwt.JwtAccessTokenValidator;
import org.picketlink.auth.oauth.jwt.JwtSettings;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.model.TokenRequest;

class JwtClientCredentialsTokenServiceTest {

    private JwtClientCredentialsTokenService tokenService;
    private JwtSettings jwtSettings;

    @BeforeEach
    void setUp() {
        jwtSettings = new JwtSettings("http://localhost/auth", "test-secret", 3600L);
        InMemoryClientRegistry registry = new InMemoryClientRegistry();
        registry.register(RegisteredClient.builder("it-client", "it-secret")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                .build());
        ClientCredentialsAuthenticator authenticator =
                new ClientCredentialsAuthenticator(registry, new ConstantTimeClientSecretMatcher());
        JwtAccessTokenIssuer issuer = new JwtAccessTokenIssuer(jwtSettings);
        tokenService = new JwtClientCredentialsTokenService(
                authenticator,
                issuer,
                jwtSettings,
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
    }

    @Test
    void issuesJwtAccessToken() {
        TokenRequest request = TokenRequest.builder()
                .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                .scope("api.read")
                .formParameter("client_id", "it-client")
                .formParameter("client_secret", "it-secret")
                .build();
        String accessToken = tokenService.issueToken(request).getAccessToken();
        assertTrue(accessToken.split("\\.").length == 3);
        JwtAccessTokenValidator validator = new JwtAccessTokenValidator(jwtSettings, new JwtAccessTokenValidator.Clock() {
            public Instant now() {
                return Instant.parse("2026-01-01T00:00:00Z");
            }
        });
        assertEquals("it-client", validator.validate(accessToken).getClientId());
    }
}
