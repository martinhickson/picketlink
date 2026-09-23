package org.picketlink.auth.oauth.grant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ClientRegistry;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.InMemoryClientRegistry;
import org.picketlink.auth.oauth.grant.ResourceOwnerAuthenticator.ResourceOwner;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.token.InMemoryRefreshTokenStore;

class PasswordAndRefreshGrantTest {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    private GrantDispatcher dispatcher;
    private InMemoryRefreshTokenStore refreshTokens;

    @BeforeEach
    void setUp() {
        ClientRegistry clients = new InMemoryClientRegistry();
        clients.register(RegisteredClient.builder("demo", "secret")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                .build());
        clients.register(RegisteredClient.builder("other", "other-secret")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                .build());
        ClientCredentialsAuthenticator clientsAuth = new ClientCredentialsAuthenticator(clients,
                new ConstantTimeClientSecretMatcher());
        refreshTokens = new InMemoryRefreshTokenStore(clock);
        ResourceOwnerAuthenticator users = (username, password) -> {
            if (!"user1".equals(username) || !"password1".equals(password)) {
                throw new OAuthException(
                        new org.picketlink.auth.oauth.model.OAuthErrorResponse(OAuthConstants.INVALID_GRANT,
                                "invalid resource owner"),
                        400);
            }
            return new ResourceOwner("user1", Set.of("api.read"));
        };
        SubjectAccessTokenIssuer issuer = (subject, clientId, scopes, issuedAt) -> "access-" + subject;
        PasswordGrantHandler password = new PasswordGrantHandler(clientsAuth, users, issuer, refreshTokens,
                Duration.ofHours(1), 3600L, clock);
        RefreshTokenGrantHandler refresh = new RefreshTokenGrantHandler(clientsAuth, issuer, refreshTokens, 3600L,
                clock);
        dispatcher = new GrantDispatcher(List.of(password, refresh));
    }

    @Test
    void passwordGrantReturnsAccessAndRefresh() {
        TokenResponse response = dispatcher.issue(passwordRequest("user1", "password1"));
        assertEquals("access-user1", response.getAccessToken());
        assertTrue(response.getRefreshToken() != null && !response.getRefreshToken().isBlank());
    }

    @Test
    void passwordGrantRejectsUnknownUser() {
        OAuthException error = assertThrows(OAuthException.class,
                () -> dispatcher.issue(passwordRequest("user1", "nope")));
        assertEquals(OAuthConstants.INVALID_GRANT, error.getError().getError());
    }

    @Test
    void refreshRotatesAndRejectsThePresentedToken() {
        TokenResponse first = dispatcher.issue(passwordRequest("user1", "password1"));
        TokenResponse second = dispatcher.issue(refreshRequest(first.getRefreshToken()));
        assertNotEquals(first.getRefreshToken(), second.getRefreshToken());
        assertThrows(OAuthException.class, () -> dispatcher.issue(refreshRequest(first.getRefreshToken())));
    }

    @Test
    void refreshRejectsATokenPresentedByAnotherClient() {
        TokenResponse first = dispatcher.issue(passwordRequest("user1", "password1"));
        OAuthException error = assertThrows(OAuthException.class,
                () -> dispatcher.issue(refreshRequest(first.getRefreshToken(), "other", "other-secret")));
        assertEquals(OAuthConstants.INVALID_GRANT, error.getError().getError());
        TokenResponse again = dispatcher.issue(refreshRequest(first.getRefreshToken()));
        assertEquals("access-user1", again.getAccessToken());
    }

    @Test
    void refreshRejectsExpiredToken() {
        TokenResponse first = dispatcher.issue(passwordRequest("user1", "password1"));
        clock.now = clock.now.plus(Duration.ofHours(2));
        assertThrows(OAuthException.class, () -> dispatcher.issue(refreshRequest(first.getRefreshToken())));
    }

    @Test
    void unsupportedGrantIsRejected() {
        TokenRequest request = TokenRequest.builder().grantType("implicit").build();
        OAuthException error = assertThrows(OAuthException.class, () -> dispatcher.issue(request));
        assertEquals(OAuthConstants.UNSUPPORTED_GRANT_TYPE, error.getError().getError());
    }

    private static TokenRequest passwordRequest(String username, String password) {
        return TokenRequest.builder()
                .grantType(OAuthConstants.PASSWORD_GRANT)
                .formParameter(OAuthConstants.GRANT_TYPE, OAuthConstants.PASSWORD_GRANT)
                .formParameter(OAuthConstants.USERNAME, username)
                .formParameter(OAuthConstants.PASSWORD, password)
                .formParameter(OAuthConstants.CLIENT_ID, "demo")
                .formParameter(OAuthConstants.CLIENT_SECRET, "secret")
                .build();
    }

    private static TokenRequest refreshRequest(String refreshToken) {
        return refreshRequest(refreshToken, "demo", "secret");
    }

    private static TokenRequest refreshRequest(String refreshToken, String clientId, String clientSecret) {
        return TokenRequest.builder()
                .grantType(OAuthConstants.REFRESH_TOKEN_GRANT)
                .formParameter(OAuthConstants.GRANT_TYPE, OAuthConstants.REFRESH_TOKEN_GRANT)
                .formParameter(OAuthConstants.REFRESH_TOKEN, refreshToken)
                .formParameter(OAuthConstants.CLIENT_ID, clientId)
                .formParameter(OAuthConstants.CLIENT_SECRET, clientSecret)
                .build();
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
