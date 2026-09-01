package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.store.DriverManagerConnectionSource;

/**
 * PL-103 RP-initiated logout, PL-104 request-parameter rejection and PL-105 persistent
 * refresh tokens (SQLite-backed, restart survival, replay detection across restart).
 */
@ExtendWith(MockitoExtension.class)
class LogoutAndStoreTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String REDIRECT_URI = "https://rp.example.test/callback";
    private static final String CLIENT_ID = "rp-client";
    private static final String CLIENT_SECRET = "rp-secret";

    @TempDir
    Path tempDir;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private AuthorizationEndpointServlet authorize;
    private LogoutEndpointServlet logout;
    private StringWriter responseWriter;

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                tempDir.resolve("keys.p12").toString());
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer).build();
        authorize = new AuthorizationEndpointServlet(server);
        logout = new LogoutEndpointServlet(server);
        responseWriter = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    private String mintIdToken() {
        TokenResponse token = server.getIssuanceServer().getTokenService().issueToken(TokenRequest.builder()
                .grantType("client_credentials")
                .authorizationHeader("Basic " + java.util.Base64.getEncoder()
                        .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()))
                .build());
        return token.getAccessToken();
    }

    private void params(Map<String, String> values) {
        values.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
    }

    @Test
    void shouldRedirectToRegisteredPostLogoutUriWithValidIdTokenHint() throws Exception {
        String idToken = mintIdToken();
        Map<String, String> params = new LinkedHashMap<>();
        params.put("id_token_hint", idToken);
        params.put("post_logout_redirect_uri", REDIRECT_URI);
        params.put("state", "s-1");
        params(params);
        logout.doGet(request, response);

        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        assertEquals(REDIRECT_URI + "?state=s-1", location.getValue());
        verify(response).setStatus(302);
    }

    @Test
    void shouldNeverRedirectToUnregisteredUri() throws Exception {
        String idToken = mintIdToken();
        Map<String, String> params = new LinkedHashMap<>();
        params.put("id_token_hint", idToken);
        params.put("post_logout_redirect_uri", "https://evil.example/steal");
        params(params);
        logout.doGet(request, response);

        verify(response).setStatus(200);
        org.mockito.Mockito.verify(response, org.mockito.Mockito.never())
                .setHeader(org.mockito.ArgumentMatchers.eq("Location"),
                        org.mockito.ArgumentMatchers.anyString());
        assertTrue(responseWriter.toString().contains("Signed out"));
    }

    @Test
    void shouldNotRedirectWithGarbageIdTokenHint() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("id_token_hint", "not-a-jwt");
        params.put("post_logout_redirect_uri", REDIRECT_URI);
        params(params);
        logout.doGet(request, response);

        verify(response).setStatus(200);
        org.mockito.Mockito.verify(response, org.mockito.Mockito.never())
                .setHeader(org.mockito.ArgumentMatchers.eq("Location"),
                        org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void shouldRejectRequestParameterExplicitly() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("request", "eyJhbGciOiJub25lIn0.e30.");
        params(params);
        authorize.doGet(request, response);
        verify(response).setStatus(400);
    }

    @Test
    void refreshTokensShouldSurviveRestartWithJdbcStore() throws Exception {
        DriverManagerConnectionSource source = new DriverManagerConnectionSource(
                "jdbc:sqlite:" + tempDir.resolve("refresh.db"), null, null);
        Clock clock = Clock.systemUTC();

        String original;
        String rotated;
        {
            RefreshTokenService first = new RefreshTokenService(clock, new JdbcRefreshTokenStore(source));
            original = first.create(CLIENT_ID, "alice", "openid", "n-1");
            RefreshTokenService.Rotation rotation = first.rotate(original).orElseThrow();
            rotated = rotation.getNewRefreshToken();
            assertEquals("alice", rotation.getSubject());
        }

        // restart: brand-new service instance over the same database
        RefreshTokenService second = new RefreshTokenService(clock, new JdbcRefreshTokenStore(source));

        // the rotated token still works; the retired one still fails and still revokes the family
        RefreshTokenService.Rotation afterRestart = second.rotate(rotated).orElseThrow();
        assertEquals("alice", afterRestart.getSubject());

        assertFalse(second.rotate(original).isPresent(), "replayed retired token must fail");
        // family revoked: the newest token no longer works either
        assertFalse(second.rotate(afterRestart.getNewRefreshToken()).isPresent(),
                "family must be revoked after replay detection");
    }
}
