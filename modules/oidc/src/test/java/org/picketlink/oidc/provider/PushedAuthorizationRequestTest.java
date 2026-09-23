package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * PL-114: Pushed Authorization Requests (RFC 9126) and max_age enforcement — the
 * FAPI-style flow where nothing sensitive transits the front channel.
 */
@ExtendWith(MockitoExtension.class)
class PushedAuthorizationRequestTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String REDIRECT_URI = "https://rp.example.test/callback";
    private static final String CLIENT_ID = "fapi-client";
    private static final String CLIENT_SECRET = "fapi-secret";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private PushedAuthorizationRequestServlet par;
    private AuthorizationEndpointServlet authorize;
    private OidcTokenEndpointServlet token;
    private StringWriter writer;

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                java.nio.file.Files.createTempDirectory("plk-par").resolve("k.p12").toString());
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(
                        Map.of("alice", "wonderland")))
                .build();
        par = new PushedAuthorizationRequestServlet(server);
        authorize = new AuthorizationEndpointServlet(server);
        token = new OidcTokenEndpointServlet(server);
        writer = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(writer));
    }

    private void form(String content) throws java.io.IOException {
        lenient().when(request.getInputStream()).thenReturn(inputStream(content));
    }

    private void basicAuth() {
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
    }

    /** RFC 9126 flow: push params, authorize with request_uri only, exchange, nonce arrives. */
    @Test
    void pushedRequestUriDrivesTheWholeFlow() throws Exception {
        // 1. push (back channel, client authenticated): nonce and PKCE never touch the browser
        form("response_type=code&redirect_uri=" + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=openid&state=s-1&nonce=n-par-1"
                + "&code_challenge=" + AuthorizationCodeService.s256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                + "&code_challenge_method=S256");
        basicAuth();
        par.doPost(request, response);
        verify(response).setStatus(201);
        String parBody = writer.toString();
        assertTrue(parBody.contains("\"request_uri\":\"urn:ietf:params:oauth:request_uri:"));
        assertTrue(parBody.contains("\"expires_in\":"));
        String requestUri = parBody.split("\"request_uri\":\"")[1].split("\"")[0];

        // 2. authorize (front channel): only client_id + request_uri
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        params(new LinkedHashMap<>(Map.of(
                "client_id", CLIENT_ID,
                "request_uri", requestUri,
                "username", "alice",
                "password", "wonderland")));
        authorize.doPost(request, response);
        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "?code="));
        assertTrue(redirect.contains("state=s-1"));
        String code = redirect.substring((REDIRECT_URI + "?code=").length(), redirect.indexOf('&'));

        // 3. exchange: the pushed PKCE verifier works and the pushed nonce reaches the ID token
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        form("grant_type=authorization_code&code=" + code
                + "&redirect_uri=" + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&code_verifier=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        basicAuth();
        token.doPost(request, response);
        verify(response).setStatus(200);
        String idToken = writer.toString().split("\"id_token\":\"")[1].split("\"")[0];
        String payload = new String(Base64.getUrlDecoder().decode(idToken.split("\\.")[1]),
                StandardCharsets.UTF_8);
        assertTrue(payload.contains("n-par-1"), "pushed nonce must reach the ID token");
        assertTrue(payload.contains("\"sid\""), "ID token must carry a session id");
    }

    @Test
    void pushedRequestUriIsSingleUseAndClientBound() throws Exception {
        form("response_type=code&redirect_uri="
                + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=openid&code_challenge=" + AuthorizationCodeService.s256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") + "&code_challenge_method=S256");
        basicAuth();
        par.doPost(request, response);
        String requestUri = writer.toString().split("\"request_uri\":\"")[1].split("\"")[0];

        // first use succeeds (fails at login, not at request_uri validation)
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        params(new LinkedHashMap<>(Map.of("client_id", CLIENT_ID, "request_uri", requestUri)));
        authorize.doGet(request, response);
        verify(response).setStatus(200);

        // second use of the same request_uri is rejected (single use)
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        params(new LinkedHashMap<>(Map.of("client_id", CLIENT_ID, "request_uri", requestUri)));
        authorize.doGet(request, response);
        verify(response).setStatus(400);

        // another client's request_uri is rejected (client-bound)
        form("response_type=code&redirect_uri="
                + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=openid&code_challenge=" + AuthorizationCodeService.s256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") + "&code_challenge_method=S256");
        basicAuth();
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        par.doPost(request, response);
        String otherUri = writer.toString().split("\"request_uri\":\"")[1].split("\"")[0];
        org.mockito.Mockito.clearInvocations(response);
        params(new LinkedHashMap<>(Map.of("client_id", "auth-admin", "request_uri", otherUri)));
        authorize.doGet(request, response);
        verify(response).setStatus(400);

        // the owner's request_uri is still usable after the other client presented it
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        params(new LinkedHashMap<>(Map.of("client_id", CLIENT_ID, "request_uri", otherUri)));
        authorize.doGet(request, response);
        verify(response).setStatus(200);
    }

    @Test
    void maxAgeIsEnforcedAtTokenExchange() throws Exception {
        // authorization with a zero-second max_age: by the time the code is exchanged the
        // authentication is already too old -> invalid_grant (fail closed per OIDC Core)
        writer.getBuffer().setLength(0);
        params(new LinkedHashMap<>(java.util.Map.of(
                "response_type", "code",
                "client_id", CLIENT_ID,
                "redirect_uri", REDIRECT_URI,
                "scope", "openid",
                "max_age", "0",
                "code_challenge", AuthorizationCodeService.s256(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                "code_challenge_method", "S256",
                "username", "alice",
                "password", "wonderland")));
        authorize.doPost(request, response);
        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String code = location.getValue()
                .substring((REDIRECT_URI + "?code=").length(),
                        location.getValue().indexOf('&'));

        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        form("grant_type=authorization_code&code=" + code
                + "&redirect_uri=" + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&code_verifier=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        basicAuth();
        token.doPost(request, response);
        verify(response).setStatus(400);
        assertTrue(writer.toString().contains("max_age"));
    }

    @Test
    void pushedRequestRejectsAnUnregisteredScope() throws Exception {
        form("response_type=code&redirect_uri=" + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=admin"
                + "&code_challenge=" + AuthorizationCodeService.s256(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                + "&code_challenge_method=S256");
        basicAuth();
        par.doPost(request, response);
        verify(response).setStatus(400);
        assertTrue(writer.toString().contains("not registered"));
    }

    @Test
    void discoveryAdvertisesTheParEndpoint() throws Exception {
        org.mockito.Mockito.clearInvocations(response);
        new DiscoveryServlet(ISSUER, "").doGet(request, response);
        assertTrue(writer.toString().contains("pushed_authorization_request_endpoint"));
        assertTrue(writer.toString().contains("/par"));
    }

    private void params(Map<String, String> values) throws java.io.IOException {
        values.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
    }

    private static jakarta.servlet.ServletInputStream inputStream(String content) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return new jakarta.servlet.ServletInputStream() {
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
            public void setReadListener(jakarta.servlet.ReadListener listener) {
            }
        };
    }
}
