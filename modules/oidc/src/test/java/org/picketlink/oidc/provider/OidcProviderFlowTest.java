package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;

/** End-to-end OIDC authorization-code + PKCE flow, refresh rotation, and the negative paths. */
@ExtendWith(MockitoExtension.class)
class OidcProviderFlowTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String REDIRECT_URI = "https://rp.example.test/callback";
    private static final String CLIENT_ID = "rp-client";
    private static final String CLIENT_SECRET = "rp-secret";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private AuthorizationEndpointServlet authorize;
    private OidcTokenEndpointServlet token;
    private UserInfoServlet userinfo;

    @BeforeEach
    void setUp() throws Exception {
        Map<String, String> users = new LinkedHashMap<>();
        users.put("alice", "wonderland");
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .scope("profile")
                .redirectUri(REDIRECT_URI)
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(users))
                .build();
        authorize = new AuthorizationEndpointServlet(server);
        token = new OidcTokenEndpointServlet(server);
        userinfo = new UserInfoServlet(server);
    }

    private StringWriter writer() throws Exception {
        StringWriter stringWriter = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(stringWriter));
        return stringWriter;
    }

    private void postAuthorize(Map<String, String> params) throws Exception {
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        writer();
        authorize.doPost(request, response);
    }

    private String authorizeCode() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid profile");
        params.put("state", "xyz");
        params.put("nonce", "n-123");
        params.put("code_challenge", AuthorizationCodeService.s256("verifier-123"));
        params.put("code_challenge_method", "S256");
        params.put("username", "alice");
        params.put("password", "wonderland");
        postAuthorize(params);
        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "?code="));
        assertTrue(redirect.contains("state=xyz"));
        return redirect.substring((REDIRECT_URI + "?code=").length(), redirect.indexOf('&'));
    }

    private Map<String, Object> tokenResponse(Map<String, String> form) throws Exception {
        StringBuilder body = new StringBuilder();
        form.forEach((name, value) -> {
            if (body.length() > 0) {
                body.append('&');
            }
            body.append(name).append('=').append(java.net.URLEncoder.encode(value, StandardCharsets.UTF_8));
        });
        when(request.getInputStream()).thenReturn(body(body.toString()));
        when(request.getHeader("Authorization")).thenReturn("Basic " + java.util.Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
        StringWriter stringWriter = writer();
        token.doPost(request, response);
        verify(response, org.mockito.Mockito.atLeastOnce()).setStatus(HttpServletResponse.SC_OK);
        return parseJson(stringWriter.toString());
    }

    @Test
    void shouldCompleteAuthorizationCodeFlowWithPkce() throws Exception {
        String code = authorizeCode();
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", REDIRECT_URI);
        form.put("code_verifier", "verifier-123");
        Map<String, Object> json = tokenResponse(form);

        assertNotNull(json.get("access_token"));
        assertNotNull(json.get("id_token"));
        assertNotNull(json.get("refresh_token"));
        assertEquals("Bearer", json.get("token_type"));

        // subject is the end-user, not the client
        var claims = server.getIssuanceServer().getIssuanceManager()
                .validate((String) json.get("access_token"));
        assertEquals("alice", claims.getSubject());

        // id token carries the nonce
        String idToken = (String) json.get("id_token");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(
                idToken.split("\\.")[1]), StandardCharsets.UTF_8);
        assertTrue(payload.contains("n-123"));
        assertTrue(payload.contains("alice"));

        // userinfo resolves the subject from the access token
        when(request.getHeader("Authorization")).thenReturn("Bearer " + json.get("access_token"));
        StringWriter userinfoWriter = writer();
        userinfo.doGet(request, response);
        assertTrue(userinfoWriter.toString().contains("\"sub\":\"alice\""));
    }

    @Test
    void shouldRejectWrongPkceVerifier() throws Exception {
        String code = authorizeCode();
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", REDIRECT_URI);
        form.put("code_verifier", "wrong-verifier");
        StringBuilder body = new StringBuilder("grant_type=authorization_code&code=" + code
                + "&redirect_uri=" + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&code_verifier=wrong-verifier");
        when(request.getInputStream()).thenReturn(body(body.toString()));
        when(request.getHeader("Authorization")).thenReturn("Basic " + java.util.Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
        writer();
        token.doPost(request, response);
        verify(response).setStatus(400);
    }

    @Test
    void shouldRejectReplayedAuthorizationCode() throws Exception {
        String code = authorizeCode();
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", REDIRECT_URI);
        form.put("code_verifier", "verifier-123");
        assertNotNull(tokenResponse(form));

        // second use of the same code must fail (single use)
        when(request.getInputStream()).thenReturn(body(
                "grant_type=authorization_code&code=" + code
                        + "&redirect_uri=" + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                        + "&code_verifier=verifier-123"));
        writer();
        token.doPost(request, response);
        verify(response).setStatus(400);
    }

    @Test
    void shouldRotateRefreshTokensAndDetectReuse() throws Exception {
        String code = authorizeCode();
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", REDIRECT_URI);
        form.put("code_verifier", "verifier-123");
        Map<String, Object> first = tokenResponse(form);
        String refreshToken = (String) first.get("refresh_token");

        // rotation: old refresh token is exchanged for a new one
        Map<String, String> refreshForm = new LinkedHashMap<>();
        refreshForm.put("grant_type", "refresh_token");
        refreshForm.put("refresh_token", refreshToken);
        Map<String, Object> rotated = tokenResponse(refreshForm);
        String newRefreshToken = (String) rotated.get("refresh_token");
        assertFalse(refreshToken.equals(newRefreshToken));
        var claims = server.getIssuanceServer().getIssuanceManager()
                .validate((String) rotated.get("access_token"));
        assertEquals("alice", claims.getSubject());

        // replaying the retired token must fail AND revoke the family
        when(request.getInputStream()).thenReturn(body(
                "grant_type=refresh_token&refresh_token="
                        + java.net.URLEncoder.encode(refreshToken, StandardCharsets.UTF_8)));
        writer();
        token.doPost(request, response);
        verify(response).setStatus(400);

        when(request.getInputStream()).thenReturn(body(
                "grant_type=refresh_token&refresh_token="
                        + java.net.URLEncoder.encode(newRefreshToken, StandardCharsets.UTF_8)));
        writer();
        token.doPost(request, response);
        verify(response, org.mockito.Mockito.times(2)).setStatus(400);
    }

    @Test
    void shouldRejectUnregisteredRedirectUri() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", "https://evil.example/steal");
        postAuthorize(params);
        verify(response).setStatus(400);
    }

    @Test
    void shouldRejectBadCredentials() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("username", "alice");
        params.put("password", "wrong");
        postAuthorize(params);
        verify(response).setStatus(401);
    }

    @Test
    void shouldRejectPkcePlainMethod() throws Exception {
        lenient().when(request.getParameter("response_type")).thenReturn("code");
        lenient().when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
        lenient().when(request.getParameter("redirect_uri")).thenReturn(REDIRECT_URI);
        lenient().when(request.getParameter("code_challenge")).thenReturn("challenge");
        lenient().when(request.getParameter("code_challenge_method")).thenReturn("plain");
        writer();
        authorize.doGet(request, response);
        verify(response).setStatus(400);
    }

    /** ServletInputStream over fixed form content. */
    private static jakarta.servlet.ServletInputStream body(String content) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return new jakarta.servlet.ServletInputStream() {
            private int position;

            @Override
            public int read() {
                if (position >= bytes.length) {
                    return -1;
                }
                return bytes[position++];
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
            public void setReadListener(jakarta.servlet.ReadListener listener) {
            }
        };
    }

    /** Minimal JSON object parser for the flat token response. */
    private static Map<String, Object> parseJson(String json) {
        Map<String, Object> values = new LinkedHashMap<>();
        int index = 1; // skip '{'
        while (index < json.length()) {
            int keyStart = json.indexOf('"', index);
            if (keyStart < 0) {
                break;
            }
            int keyEnd = json.indexOf('"', keyStart + 1);
            int colon = json.indexOf(':', keyEnd + 1);
            int valueStart = colon + 1;
            while (Character.isWhitespace(json.charAt(valueStart))) {
                valueStart++;
            }
            int valueEnd = valueStart;
            while (valueEnd < json.length() && ",}".indexOf(json.charAt(valueEnd)) < 0) {
                valueEnd++;
            }
            String raw = json.substring(valueStart, valueEnd).trim();
            if (raw.startsWith("\"")) {
                values.put(json.substring(keyStart + 1, keyEnd), raw.substring(1, raw.length() - 1));
            } else {
                values.put(json.substring(keyStart + 1, keyEnd), Long.valueOf(raw));
            }
            index = valueEnd;
        }
        return values;
    }
}
