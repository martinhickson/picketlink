package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;

/** Refresh tokens stay bound to their client, and max_age follows the server clock. */
@ExtendWith(MockitoExtension.class)
class RefreshAndMaxAgeTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String REDIRECT_URI = "https://rp.example.test/callback";
    private static final String CLIENT_ID = "rp-client";
    private static final String CLIENT_SECRET = "rp-secret";
    private static final String OTHER_ID = "other-client";
    private static final String OTHER_SECRET = "other-secret";
    private static final String VERIFIER = "a".repeat(43);

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Test
    void wrongClientDoesNotBurnTheRefreshToken() throws Exception {
        OidcProviderServer server = server(Clock.systemUTC());
        String refresh = refreshToken(server, CLIENT_ID, CLIENT_SECRET);
        StringWriter rejected = post(server, "grant_type=refresh_token&refresh_token=" + enc(refresh),
                OTHER_ID, OTHER_SECRET);
        verify(response).setStatus(400);
        assertTrue(rejected.toString().contains("not issued to this client"));

        org.mockito.Mockito.clearInvocations(response);
        StringWriter rotated = post(server, "grant_type=refresh_token&refresh_token=" + enc(refresh),
                CLIENT_ID, CLIENT_SECRET);
        verify(response).setStatus(200);
        assertTrue(rotated.toString().contains("\"refresh_token\""));
    }

    @Test
    void refreshCannotWidenScopeAndKeepsTheToken() throws Exception {
        OidcProviderServer server = server(Clock.systemUTC());
        String refresh = refreshToken(server, CLIENT_ID, CLIENT_SECRET);
        post(server, "grant_type=refresh_token&refresh_token=" + enc(refresh) + "&scope=admin",
                CLIENT_ID, CLIENT_SECRET);
        verify(response).setStatus(400);

        org.mockito.Mockito.clearInvocations(response);
        StringWriter narrowed = post(server,
                "grant_type=refresh_token&refresh_token=" + enc(refresh) + "&scope=openid",
                CLIENT_ID, CLIENT_SECRET);
        verify(response).setStatus(200);
        assertTrue(narrowed.toString().contains("\"scope\":\"openid\""));
        assertTrue(!narrowed.toString().contains("\"scope\":\"openid profile\""));
    }

    @Test
    void maxAgeUsesTheServerClock() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2020-01-01T00:00:00Z"), ZoneOffset.UTC);
        OidcProviderServer server = server(clock);
        String code = authorizationCode(server, "60");
        post(server, "grant_type=authorization_code&code=" + enc(code)
                + "&redirect_uri=" + enc(REDIRECT_URI)
                + "&code_verifier=" + VERIFIER,
                CLIENT_ID, CLIENT_SECRET);
        verify(response).setStatus(200);
    }

    private OidcProviderServer server(Clock clock) throws Exception {
        Map<String, String> users = new LinkedHashMap<>();
        users.put("alice", "wonderland");
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .scope("profile")
                .redirectUri(REDIRECT_URI)
                .build());
        issuanceServer.getClientStore().save(RegisteredClient.builder(OTHER_ID, OTHER_SECRET)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .build());
        return OidcProviderServer.builder(ISSUER, issuanceServer)
                .clock(clock)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(users))
                .build();
    }

    private String refreshToken(OidcProviderServer server, String clientId, String secret) throws Exception {
        String code = authorizationCode(server, null);
        StringWriter body = post(server, "grant_type=authorization_code&code=" + enc(code)
                + "&redirect_uri=" + enc(REDIRECT_URI)
                + "&code_verifier=" + VERIFIER,
                clientId, secret);
        verify(response).setStatus(200);
        String json = body.toString();
        org.mockito.Mockito.clearInvocations(response);
        return json.split("\"refresh_token\":\"")[1].split("\"")[0];
    }

    private String authorizationCode(OidcProviderServer server, String maxAge) throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid profile");
        params.put("state", "xyz");
        params.put("code_challenge", AuthorizationCodeService.s256(VERIFIER));
        params.put("code_challenge_method", "S256");
        params.put("username", "alice");
        params.put("password", "wonderland");
        if (maxAge != null) {
            params.put("max_age", maxAge);
        }
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        new AuthorizationEndpointServlet(server).doPost(request, response);
        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "?code="));
        org.mockito.Mockito.clearInvocations(response);
        return redirect.substring((REDIRECT_URI + "?code=").length(), redirect.indexOf('&'));
    }

    private StringWriter post(OidcProviderServer server, String form, String clientId, String secret)
            throws Exception {
        when(request.getInputStream()).thenReturn(stream(form));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8)));
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        new OidcTokenEndpointServlet(server).doPost(request, response);
        return writer;
    }

    private static String enc(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static ServletInputStream stream(String content) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return new ServletInputStream() {
            private int position;

            @Override
            public int read() {
                return position >= bytes.length ? -1 : bytes[position++];
            }

            @Override
            public boolean isFinished() {
                return position >= bytes.length;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
            }
        };
    }
}
