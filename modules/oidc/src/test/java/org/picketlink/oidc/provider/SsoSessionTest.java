package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;

/** One browser session signs a second client in and shares that session id. */
@ExtendWith(MockitoExtension.class)
class SsoSessionTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String REDIRECT_A = "https://a.example/cb";
    private static final String REDIRECT_B = "https://b.example/cb";
    private static final String CLIENT_A = "client-a";
    private static final String CLIENT_B = "client-b";
    private static final String SECRET = "sso-secret";
    private static final String VERIFIER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private AuthorizationEndpointServlet authorize;
    private OidcTokenEndpointServlet token;
    private final Map<String, Object> sessionAttributes = new LinkedHashMap<>();

    @BeforeEach
    void setUp() throws Exception {
        Map<String, String> users = new LinkedHashMap<>();
        users.put("alice", "wonderland");
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_A, SECRET)
                .scope("openid").redirectUri(REDIRECT_A).build());
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_B, SECRET)
                .scope("openid").redirectUri(REDIRECT_B).build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(users))
                .build();
        authorize = new AuthorizationEndpointServlet(server);
        token = new OidcTokenEndpointServlet(server);

        HttpSession session = mock(HttpSession.class);
        lenient().when(session.getAttribute(anyString()))
                .thenAnswer(invocation -> sessionAttributes.get(invocation.getArgument(0)));
        lenient().doAnswer(invocation -> {
            sessionAttributes.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(session).setAttribute(anyString(), any());
        lenient().doAnswer(invocation -> {
            sessionAttributes.clear();
            return null;
        }).when(session).invalidate();
        lenient().when(request.getSession(true)).thenReturn(session);
        lenient().when(request.getSession(false)).thenReturn(session);
    }

    @Test
    void secondClientSignsInSilentlyWithTheSameSessionId() throws Exception {
        String codeA = login(CLIENT_A, REDIRECT_A);
        String codeB = silent(CLIENT_B, REDIRECT_B);
        String sidA = sidOf(redeem(CLIENT_A, SECRET, REDIRECT_A, codeA));
        String sidB = sidOf(redeem(CLIENT_B, SECRET, REDIRECT_B, codeB));
        assertEquals(sidA, sidB);
        assertFalse(sidA.isBlank());
    }

    @Test
    void promptLoginStillShowsTheFormWhenASessionExists() throws Exception {
        login(CLIENT_A, REDIRECT_A);
        org.mockito.Mockito.clearInvocations(response);
        StringWriter writer = writer();
        parameters(CLIENT_B, REDIRECT_B, "login", null);
        authorize.doGet(request, response);
        verify(response).setStatus(200);
        assertTrue(writer.toString().contains("password"));
        org.mockito.Mockito.verify(response, org.mockito.Mockito.never())
                .setHeader(eq("Location"), anyString());
    }

    @Test
    void maxAgeZeroDoesNotReuseTheSession() throws Exception {
        login(CLIENT_A, REDIRECT_A);
        org.mockito.Mockito.clearInvocations(response);
        StringWriter writer = writer();
        parameters(CLIENT_B, REDIRECT_B, null, "0");
        authorize.doGet(request, response);
        verify(response).setStatus(200);
        assertTrue(writer.toString().contains("password"));
        assertFalse(writer.toString().contains("code="));
    }

    @Test
    void logoutEndsTheBrowserSession() throws Exception {
        login(CLIENT_A, REDIRECT_A);
        assertFalse(sessionAttributes.isEmpty());
        lenient().when(request.getParameter(anyString())).thenReturn(null);
        writer();
        new LogoutEndpointServlet(server).doGet(request, response);
        assertTrue(sessionAttributes.isEmpty());
        org.mockito.Mockito.clearInvocations(response);
        parameters(CLIENT_B, REDIRECT_B, "none", null);
        authorize.doGet(request, response);
        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Location"), location.capture());
        assertTrue(location.getValue().contains("error=login_required"));
    }

    private String login(String clientId, String redirectUri) throws Exception {
        parameters(clientId, redirectUri, null, null);
        lenient().when(request.getParameter("username")).thenReturn("alice");
        lenient().when(request.getParameter("password")).thenReturn("wonderland");
        authorize.doPost(request, response);
        return captureCode(redirectUri);
    }

    private String silent(String clientId, String redirectUri) throws Exception {
        org.mockito.Mockito.clearInvocations(response);
        parameters(clientId, redirectUri, "none", null);
        authorize.doGet(request, response);
        return captureCode(redirectUri);
    }

    private void parameters(String clientId, String redirectUri, String prompt, String maxAge) {
        lenient().when(request.getParameter(anyString())).thenReturn(null);
        lenient().when(request.getParameter("response_type")).thenReturn("code");
        lenient().when(request.getParameter("client_id")).thenReturn(clientId);
        lenient().when(request.getParameter("redirect_uri")).thenReturn(redirectUri);
        lenient().when(request.getParameter("scope")).thenReturn("openid");
        lenient().when(request.getParameter("state")).thenReturn("xyz");
        lenient().when(request.getParameter("nonce")).thenReturn("n-1");
        lenient().when(request.getParameter("code_challenge"))
                .thenReturn(AuthorizationCodeService.s256(VERIFIER));
        lenient().when(request.getParameter("code_challenge_method")).thenReturn("S256");
        if (prompt != null) {
            lenient().when(request.getParameter("prompt")).thenReturn(prompt);
        }
        if (maxAge != null) {
            lenient().when(request.getParameter("max_age")).thenReturn(maxAge);
        }
    }

    private String captureCode(String redirectUri) {
        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(redirectUri + "?code="));
        int start = (redirectUri + "?code=").length();
        return redirect.substring(start, redirect.indexOf('&', start));
    }

    private String redeem(String clientId, String secret, String redirectUri, String code)
            throws Exception {
        String body = "grant_type=authorization_code&code=" + code
                + "&redirect_uri=" + java.net.URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&code_verifier=" + VERIFIER;
        lenient().when(request.getInputStream()).thenReturn(stream(body));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic "
                + Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8)));
        lenient().when(request.getHeader("DPoP")).thenReturn(null);
        StringWriter writer = writer();
        token.doPost(request, response);
        String json = writer.toString();
        int start = json.indexOf("\"id_token\":\"") + "\"id_token\":\"".length();
        return json.substring(start, json.indexOf('"', start));
    }

    private StringWriter writer() throws Exception {
        StringWriter stringWriter = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(stringWriter));
        return stringWriter;
    }

    private static String sidOf(String idToken) {
        String payload = new String(Base64.getUrlDecoder().decode(idToken.split("\\.")[1]),
                StandardCharsets.UTF_8);
        String needle = "\"sid\":\"";
        int start = payload.indexOf(needle);
        assertNotEquals(-1, start, payload);
        start += needle.length();
        return payload.substring(start, payload.indexOf('"', start));
    }

    private static jakarta.servlet.ServletInputStream stream(String content) {
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
}
