package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;

/** Authorization-code PKCE: S256 is required, and the verifier must match RFC 7636. */
@ExtendWith(MockitoExtension.class)
class AuthorizationCodePkceTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String REDIRECT_URI = "https://rp.example.test/callback";
    private static final String CLIENT_ID = "rp-client";
    private static final String CLIENT_SECRET = "rp-secret";
    private static final String VERIFIER = "a".repeat(43);

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private AuthorizationEndpointServlet authorize;
    private OidcTokenEndpointServlet token;
    private PushedAuthorizationRequestServlet par;

    @BeforeEach
    void setUp() throws Exception {
        Map<String, String> users = new LinkedHashMap<>();
        users.put("alice", "wonderland");
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(users))
                .build();
        authorize = new AuthorizationEndpointServlet(server);
        token = new OidcTokenEndpointServlet(server);
        par = new PushedAuthorizationRequestServlet(server);
    }

    @Test
    void omitsCodeChallenge() throws Exception {
        postAuthorize(login(null, null));
        verify(response).setStatus(400);
    }

    @Test
    void emptyCodeChallenge() throws Exception {
        postAuthorize(login("", "S256"));
        verify(response).setStatus(400);
    }

    @Test
    void omitsChallengeMethod() throws Exception {
        postAuthorize(login(AuthorizationCodeService.s256(VERIFIER), null));
        verify(response).setStatus(400);
    }

    @Test
    void plainMethod() throws Exception {
        postAuthorize(login(AuthorizationCodeService.s256(VERIFIER), "plain"));
        verify(response).setStatus(400);
    }

    @Test
    void lowercaseMethod() throws Exception {
        postAuthorize(login(AuthorizationCodeService.s256(VERIFIER), "s256"));
        verify(response).setStatus(400);
    }

    @Test
    void shortChallenge() throws Exception {
        postAuthorize(login("a".repeat(42), "S256"));
        verify(response).setStatus(400);
    }

    @Test
    void paddedChallenge() throws Exception {
        postAuthorize(login(AuthorizationCodeService.s256(VERIFIER) + "=", "S256"));
        verify(response).setStatus(400);
    }

    @Test
    void challengeWithDot() throws Exception {
        String challenge = AuthorizationCodeService.s256(VERIFIER);
        postAuthorize(login(challenge.substring(0, 42) + ".", "S256"));
        verify(response).setStatus(400);
    }

    @Test
    void verifierOf43And128Characters() throws Exception {
        assertRedeemed(VERIFIER);
        org.mockito.Mockito.clearInvocations(response);
        assertRedeemed("b".repeat(128));
    }

    @Test
    void shortVerifierBurnsTheCode() throws Exception {
        String code = issue(AuthorizationCodeService.s256("short"));
        exchange(code, "short", 400);
        org.mockito.Mockito.clearInvocations(response);
        exchange(code, "short", 400);
    }

    @Test
    void verifierLongerThan128BurnsTheCode() throws Exception {
        String verifier = "c".repeat(129);
        String code = issue(AuthorizationCodeService.s256(verifier));
        exchange(code, verifier, 400);
    }

    @Test
    void verifierOutsideTheUnreservedSetBurnsTheCode() throws Exception {
        String verifier = "d".repeat(42) + " ";
        String code = issue(AuthorizationCodeService.s256(verifier));
        exchange(code, verifier, 400);
        org.mockito.Mockito.clearInvocations(response);
        String plus = "e".repeat(42) + "+";
        String plusCode = issue(AuthorizationCodeService.s256(plus));
        exchange(plusCode, plus, 400);
    }

    @Test
    void wrongVerifierCannotBeRetried() throws Exception {
        String code = issue(AuthorizationCodeService.s256(VERIFIER));
        exchange(code, "b".repeat(43), 400);
        org.mockito.Mockito.clearInvocations(response);
        exchange(code, VERIFIER, 400);
    }

    @Test
    void tildeDotHyphenAndUnderscoreAreUnreserved() {
        String verifier = "A".repeat(39) + "-._~";
        assertEquals(43, verifier.length());
        assertTrue(AuthorizationCodeService.verifierMatches(
                AuthorizationCodeService.s256(verifier), verifier));
    }

    @Test
    void anotherClientCannotBurnTheCode() {
        Clock clock = Clock.systemUTC();
        AuthorizationCodeService codes = new AuthorizationCodeService(clock);
        String code = codes.create(CLIENT_ID, REDIRECT_URI, "alice", "openid", "n",
                AuthorizationCodeService.s256(VERIFIER));
        assertTrue(codes.consume(code, VERIFIER, "other-client", REDIRECT_URI).isEmpty());
        assertTrue(codes.consume(code, VERIFIER, CLIENT_ID, REDIRECT_URI).isPresent());
    }

    @Test
    void codeIssuedWithoutAChallengeCannotBeRedeemed() {
        Clock clock = Clock.fixed(Instant.parse("2020-01-01T00:00:00Z"), ZoneOffset.UTC);
        AuthorizationCodeService codes = new AuthorizationCodeService(clock);
        String code = codes.create("c", REDIRECT_URI, "alice", "openid", "n", null);
        assertTrue(codes.consume(code, VERIFIER).isEmpty());
        assertTrue(codes.consume(code, null).isEmpty());
    }

    @Test
    void authTimeUsesTheInjectedClock() {
        Clock clock = Clock.fixed(Instant.parse("2020-01-01T00:00:00Z"), ZoneOffset.UTC);
        AuthorizationCodeService codes = new AuthorizationCodeService(clock);
        String code = codes.create("c", REDIRECT_URI, "alice", "openid", "n",
                AuthorizationCodeService.s256(VERIFIER));
        AuthorizationCodeService.PendingCode pending = codes.consume(code, VERIFIER).orElseThrow();
        assertEquals(clock.instant().getEpochSecond(), pending.getAuthTime());
    }

    @Test
    void parRejectsAMissingOrPlainChallenge() throws Exception {
        parPost("response_type=code&redirect_uri=" + enc(REDIRECT_URI) + "&scope=openid");
        verify(response).setStatus(400);
        org.mockito.Mockito.clearInvocations(response);
        parPost("response_type=code&redirect_uri=" + enc(REDIRECT_URI)
                + "&scope=openid&code_challenge=" + AuthorizationCodeService.s256(VERIFIER)
                + "&code_challenge_method=plain");
        verify(response).setStatus(400);
    }

    @Test
    void hashCompareRejectsADifferentVerifier() {
        assertFalse(AuthorizationCodeService.verifierMatches(
                AuthorizationCodeService.s256(VERIFIER), "b".repeat(43)));
    }

    private void assertRedeemed(String verifier) throws Exception {
        String code = issue(AuthorizationCodeService.s256(verifier));
        exchange(code, verifier, 200);
    }

    private String issue(String challenge) throws Exception {
        postAuthorize(login(challenge, "S256"));
        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "?code="));
        return redirect.substring((REDIRECT_URI + "?code=").length(), redirect.indexOf('&'));
    }

    private Map<String, String> login(String challenge, String method) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid");
        params.put("username", "alice");
        params.put("password", "wonderland");
        if (challenge != null) {
            params.put("code_challenge", challenge);
        }
        if (method != null) {
            params.put("code_challenge_method", method);
        }
        return params;
    }

    private void postAuthorize(Map<String, String> params) throws Exception {
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        lenient().when(request.getParameter("code_challenge")).thenReturn(params.get("code_challenge"));
        lenient().when(request.getParameter("code_challenge_method"))
                .thenReturn(params.get("code_challenge_method"));
        writer();
        authorize.doPost(request, response);
    }

    private void exchange(String code, String verifier, int expectedStatus) throws Exception {
        String body = "grant_type=authorization_code&code=" + enc(code)
                + "&redirect_uri=" + enc(REDIRECT_URI)
                + "&code_verifier=" + enc(verifier);
        when(request.getInputStream()).thenReturn(stream(body));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8)));
        writer();
        token.doPost(request, response);
        verify(response).setStatus(expectedStatus);
    }

    private void parPost(String form) throws Exception {
        when(request.getInputStream()).thenReturn(stream(form));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8)));
        writer();
        par.doPost(request, response);
    }

    private StringWriter writer() throws Exception {
        StringWriter stringWriter = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(stringWriter));
        return stringWriter;
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
