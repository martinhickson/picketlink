package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertFalse;
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

/** Profile and email claims stay inside the scopes the client was granted. */
@ExtendWith(MockitoExtension.class)
class ScopedClaimsReleaseTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String REDIRECT = "https://rp.example/cb";
    private static final String CLIENT = "rp";
    private static final String SECRET = "rp-secret";
    private static final String VERIFIER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private AuthorizationEndpointServlet authorize;
    private OidcTokenEndpointServlet token;

    @BeforeEach
    void setUp() throws Exception {
        Map<String, String> users = new LinkedHashMap<>();
        users.put("alice", "wonderland");
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("email", "alice@example.test");
        claims.put("name", "Alice Wonderland");
        claims.put("employee_id", "E-1");
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT, SECRET)
                .scope("openid").scope("profile").scope("email").redirectUri(REDIRECT).build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(users))
                .claimSource(subject -> claims)
                .build();
        authorize = new AuthorizationEndpointServlet(server);
        token = new OidcTokenEndpointServlet(server);

        HttpSession session = mock(HttpSession.class);
        lenient().when(request.getSession(true)).thenReturn(session);
        lenient().when(request.getSession(false)).thenReturn(session);
        lenient().when(session.getAttribute(anyString())).thenReturn(null);
        lenient().doAnswer(invocation -> null).when(session).setAttribute(anyString(), any());
    }

    @Test
    void openidAloneOmitsProfileAndEmail() throws Exception {
        String released = payload(tokens("openid"));
        assertFalse(released.contains("\"email\""));
        assertFalse(released.contains("\"name\""));
        assertTrue(released.contains("\"employee_id\":\"E-1\""));
        String info = userinfo(accessToken(tokens("openid")));
        assertFalse(info.contains("\"email\""));
        assertFalse(info.contains("\"name\""));
        assertTrue(info.contains("\"employee_id\":\"E-1\""));
    }

    @Test
    void profileAndEmailReleaseThoseClaims() throws Exception {
        String released = payload(tokens("openid profile email"));
        assertTrue(released.contains("\"email\":\"alice@example.test\""));
        assertTrue(released.contains("\"name\":\"Alice Wonderland\""));
        String info = userinfo(accessToken(tokens("openid profile email")));
        assertTrue(info.contains("\"email\":\"alice@example.test\""));
        assertTrue(info.contains("\"name\":\"Alice Wonderland\""));
    }

    private String tokens(String scope) throws Exception {
        lenient().when(request.getParameter(anyString())).thenReturn(null);
        lenient().when(request.getParameter("response_type")).thenReturn("code");
        lenient().when(request.getParameter("client_id")).thenReturn(CLIENT);
        lenient().when(request.getParameter("redirect_uri")).thenReturn(REDIRECT);
        lenient().when(request.getParameter("scope")).thenReturn(scope);
        lenient().when(request.getParameter("state")).thenReturn("xyz");
        lenient().when(request.getParameter("nonce")).thenReturn("n-1");
        lenient().when(request.getParameter("code_challenge"))
                .thenReturn(AuthorizationCodeService.s256(VERIFIER));
        lenient().when(request.getParameter("code_challenge_method")).thenReturn("S256");
        lenient().when(request.getParameter("username")).thenReturn("alice");
        lenient().when(request.getParameter("password")).thenReturn("wonderland");
        org.mockito.Mockito.clearInvocations(response);
        writer();
        authorize.doPost(request, response);
        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Location"), location.capture());
        String redirect = location.getValue();
        int start = (REDIRECT + "?code=").length();
        String code = redirect.substring(start, redirect.indexOf('&', start));
        String body = "grant_type=authorization_code&code=" + code
                + "&redirect_uri=" + java.net.URLEncoder.encode(REDIRECT, StandardCharsets.UTF_8)
                + "&code_verifier=" + VERIFIER;
        lenient().when(request.getInputStream()).thenReturn(stream(body));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic "
                + Base64.getEncoder().encodeToString((CLIENT + ":" + SECRET).getBytes(StandardCharsets.UTF_8)));
        lenient().when(request.getHeader("DPoP")).thenReturn(null);
        StringWriter json = writer();
        token.doPost(request, response);
        return json.toString();
    }

    private static String payload(String tokenResponse) {
        int start = tokenResponse.indexOf("\"id_token\":\"") + "\"id_token\":\"".length();
        String idToken = tokenResponse.substring(start, tokenResponse.indexOf('"', start));
        return new String(Base64.getUrlDecoder().decode(idToken.split("\\.")[1]), StandardCharsets.UTF_8);
    }

    private static String accessToken(String tokenResponse) {
        int start = tokenResponse.indexOf("\"access_token\":\"") + "\"access_token\":\"".length();
        return tokenResponse.substring(start, tokenResponse.indexOf('"', start));
    }

    private String userinfo(String accessToken) throws Exception {
        lenient().when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);
        lenient().when(request.getHeader("DPoP")).thenReturn(null);
        StringWriter body = writer();
        new UserInfoServlet(server).doGet(request, response);
        return body.toString();
    }

    private StringWriter writer() throws Exception {
        StringWriter stringWriter = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(stringWriter));
        return stringWriter;
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
