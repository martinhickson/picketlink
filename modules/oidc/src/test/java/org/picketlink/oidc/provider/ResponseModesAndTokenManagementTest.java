package org.picketlink.oidc.provider;

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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * PL-116: response modes (query/fragment/form_post/JARM), the RFC 9207 iss parameter and
 * provider-side introspection/revocation.
 */
@ExtendWith(MockitoExtension.class)
class ResponseModesAndTokenManagementTest {

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
    private StringWriter writer;

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                java.nio.file.Files.createTempDirectory("plk-rm").resolve("k.p12").toString());
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(
                        Map.of("alice", "wonderland")))
                .build();
        authorize = new AuthorizationEndpointServlet(server);
        writer = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(writer));
    }

    private void loginAs(String responseMode) throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid");
        params.put("state", "s-1");
        params.put("code_challenge", AuthorizationCodeService.s256(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        params.put("code_challenge_method", "S256");
        if (responseMode != null) {
            params.put("response_mode", responseMode);
        }
        params.put("username", "alice");
        params.put("password", "wonderland");
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        authorize.doPost(request, response);
    }

    @Test
    void defaultQueryModeCarriesIssParameter() throws Exception {
        loginAs(null);
        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "?code="));
        assertTrue(redirect.contains("iss=" + "https%3A%2F%2Fauth.example.test"),
                "RFC 9207 iss parameter must be present (mix-up mitigation)");
        assertTrue(redirect.contains("state=s-1"));
    }

    @Test
    void omittedStateIsNotEchoed() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid");
        params.put("code_challenge", AuthorizationCodeService.s256(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        params.put("code_challenge_method", "S256");
        params.put("username", "alice");
        params.put("password", "wonderland");
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        authorize.doPost(request, response);

        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "?code="));
        assertTrue(redirect.contains("iss="));
        assertTrue(!redirect.contains("state="));
    }

    @Test
    void loginFormKeepsTheResponseMode() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid");
        params.put("response_mode", "fragment");
        params.put("code_challenge", AuthorizationCodeService.s256(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        params.put("code_challenge_method", "S256");
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        authorize.doGet(request, response);
        assertTrue(writer.toString().contains("name=\"response_mode\" value=\"fragment\""));
    }

    @Test
    void promptNoneFragmentKeepsTheErrorOffTheQuery() throws Exception {
        promptNone("fragment", "s-1");
        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "#error=login_required"));
        assertTrue(redirect.contains("state=s-1"));
        assertTrue(redirect.contains("iss="));
        assertTrue(!redirect.contains("?error="));
    }

    @Test
    void promptNoneFormPostCarriesTheErrorInTheForm() throws Exception {
        promptNone("form_post", "s-1");
        verify(response).setStatus(200);
        String html = writer.toString();
        assertTrue(html.contains("name=\"error\" value=\"login_required\""));
        assertTrue(html.contains("name=\"iss\""));
        assertTrue(!html.contains("name=\"code\""));
        verify(response, org.mockito.Mockito.never())
                .setHeader(org.mockito.ArgumentMatchers.eq("Location"),
                        org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void promptNoneJarmCarriesTheErrorInsideTheResponse() throws Exception {
        promptNone("jwt", "s-1");
        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "?response="));
        String responseJwt = java.net.URLDecoder.decode(
                redirect.substring(redirect.indexOf("response=") + "response=".length()),
                StandardCharsets.UTF_8);
        org.apache.cxf.rs.security.jose.jwt.JwtClaims claims =
                server.getIssuanceServer().getSigningService()
                        .validate(responseJwt, java.util.Set.of("RS256", "ES256", "EdDSA"));
        assertEqualsSafe("login_required", claims.getClaim("error"));
        assertTrue(claims.getClaim("code") == null);
    }

    private void promptNone(String responseMode, String state) throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid");
        params.put("state", state);
        params.put("prompt", "none");
        params.put("response_mode", responseMode);
        params.put("code_challenge", AuthorizationCodeService.s256(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        params.put("code_challenge_method", "S256");
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        authorize.doGet(request, response);
    }

    @Test
    void fragmentModePutsResponseInTheFragment() throws Exception {
        loginAs("fragment");
        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "#"));
        assertTrue(redirect.contains("code="));
        assertTrue(redirect.contains("iss="));
    }

    @Test
    void formPostModeRendersAutoSubmittingForm() throws Exception {
        loginAs("form_post");
        verify(response).setStatus(200);
        String html = writer.toString();
        assertTrue(html.contains("action=\"https://rp.example.test/callback\""));
        assertTrue(html.contains("name=\"code\""));
        assertTrue(html.contains("name=\"state\""));
        assertTrue(html.contains("name=\"iss\""));
        assertTrue(html.contains("document.forms[0].submit()"));
    }

    @Test
    void jarmModeReturnsSignedResponseJwt() throws Exception {
        loginAs("jwt");
        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "?response="),
                "code flow delivers response_mode=jwt on the query");

        String responseJwt = java.net.URLDecoder.decode(
                redirect.substring(redirect.indexOf("response=") + "response=".length()),
                StandardCharsets.UTF_8);
        // the response JWT validates through the issuer's signing service
        org.apache.cxf.rs.security.jose.jwt.JwtClaims claims =
                server.getIssuanceServer().getSigningService()
                        .validate(responseJwt, java.util.Set.of("RS256", "ES256", "EdDSA"));
        assertEqualsSafe(ISSUER, claims.getIssuer());
        assertEqualsSafe(CLIENT_ID, claims.getAudience());
        assertNotNull(claims.getClaim("code"), "code must be inside the signed response");
        assertNotNull(claims.getClaim("state"), "state must be inside the signed response");
        assertNotNull(claims.getExpiryTime(), "JARM responses are short-lived");
    }

    @Test
    void unsupportedResponseModeIsRejected() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("response_mode", "websocket");
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        authorize.doPost(request, response);
        verify(response).setStatus(400);
    }

    @Test
    void introspectionAndRevocationOverProviderTokens() throws Exception {
        // mint a token through the provider's token endpoint
        OidcTokenEndpointServlet token = new OidcTokenEndpointServlet(server);
        lenient().when(request.getInputStream()).thenReturn(inputStream(
                "grant_type=client_credentials&scope=openid"));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
        token.doPost(request, response);
        String accessToken = writer.toString().split("\"access_token\":\"")[1].split("\"")[0];

        // introspect: active
        writer.getBuffer().setLength(0);
        when(request.getInputStream()).thenReturn(inputStream("token=" + accessToken));
        ProviderTokenManagementServlet.introspection(server).doPost(request, response);
        verify(response, org.mockito.Mockito.atLeastOnce()).setStatus(200);
        assertTrue(writer.toString().contains("\"active\":true"));

        // revoke it
        writer.getBuffer().setLength(0);
        when(request.getInputStream()).thenReturn(inputStream("token=" + accessToken));
        ProviderTokenManagementServlet.revocation(server).doPost(request, response);
        verify(response, org.mockito.Mockito.atLeast(2)).setStatus(200);

        // introspect again: inactive
        writer.getBuffer().setLength(0);
        when(request.getInputStream()).thenReturn(inputStream("token=" + accessToken));
        ProviderTokenManagementServlet.introspection(server).doPost(request, response);
        verify(response, org.mockito.Mockito.atLeast(3)).setStatus(200);
        assertTrue(writer.toString().contains("\"active\":false"),
                "revoked token must introspect as inactive");
    }

    @Test
    void revocationKillsARefreshToken() throws Exception {
        OidcTokenEndpointServlet token = new OidcTokenEndpointServlet(server);
        lenient().when(request.getInputStream()).thenReturn(inputStream(
                "grant_type=password&username=alice&password=wonderland&scope=openid"));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
        token.doPost(request, response);
        String refreshToken = writer.toString().split("\"refresh_token\":\"")[1].split("\"")[0];

        writer.getBuffer().setLength(0);
        when(request.getInputStream()).thenReturn(inputStream("token=" + refreshToken));
        ProviderTokenManagementServlet.revocation(server).doPost(request, response);
        verify(response, org.mockito.Mockito.atLeastOnce()).setStatus(200);

        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        when(request.getInputStream()).thenReturn(inputStream(
                "grant_type=refresh_token&refresh_token=" + refreshToken));
        token.doPost(request, response);
        verify(response).setStatus(400);
    }

    @Test
    void discoveryAdvertisesTheNewCapabilities() throws Exception {
        org.mockito.Mockito.clearInvocations(response);
        writer.getBuffer().setLength(0);
        assertNotNull(DiscoveryServlet.class.getDeclaredConstructor().newInstance());
        new DiscoveryServlet(ISSUER, "").doGet(request, response);
        String json = writer.toString();
        assertTrue(json.contains("\"authorization_endpoint\":\"" + ISSUER + "/authorize\""));
        assertTrue(json.contains("\"jwks_uri\":\"" + ISSUER + "/jwks.json\""));
        assertTrue(json.contains("introspection_endpoint"));
        assertTrue(json.contains("revocation_endpoint"));
        assertTrue(json.contains("response_modes_supported"));
        assertTrue(json.contains("\"authorization_response_iss_parameter_supported\":true"));
        assertTrue(json.contains("\"grant_types_supported\":["));
        assertTrue(json.contains("\"dpop_signing_alg_values_supported\":[\"RS256\",\"ES256\"]"));
        assertTrue(json.contains("\"backchannel_logout_supported\":true"));
        assertTrue(json.contains("\"backchannel_logout_session_supported\":true"));
        assertTrue(!json.contains("\"authorization_response_iss_parameter_supported\":\"true\""));
    }

    private static void assertEqualsSafe(Object expected, Object actual) {
        assertTrue(String.valueOf(expected).equals(String.valueOf(actual)),
                expected + " != " + actual);
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
