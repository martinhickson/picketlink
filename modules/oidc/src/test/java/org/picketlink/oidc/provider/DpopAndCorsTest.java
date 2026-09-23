package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * PL-113: DPoP-bound access tokens (RFC 9449) end-to-end, CORS for SPA clients and
 * prompt=none semantics.
 */
@ExtendWith(MockitoExtension.class)
class DpopAndCorsTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String TOKEN_URI = "https://auth.example.test/token";
    private static final String CLIENT_ID = "spa-client";
    private static final String CLIENT_SECRET = "spa-secret";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private OidcTokenEndpointServlet token;
    private UserInfoServlet userinfo;
    private KeyPair dpopKeyPair;
    private StringWriter writer;

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                java.nio.file.Files.createTempDirectory("plk-dpop").resolve("k.p12").toString());
        System.setProperty("picketlink.oidc.token.endpoint.uri", TOKEN_URI);
        System.setProperty("picketlink.oidc.userinfo.uri", "https://auth.example.test/userinfo");
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .redirectUri("https://rp.example/cb")
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer).build();
        token = new OidcTokenEndpointServlet(server);
        userinfo = new UserInfoServlet(server);
        java.security.KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        dpopKeyPair = rsaGen.generateKeyPair();
        writer = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(writer));
    }

    private String fetchAccessToken(String dpopProof) throws Exception {
        when(request.getInputStream()).thenReturn(body(
                "grant_type=client_credentials&scope=openid"));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
        if (dpopProof != null) {
            lenient().when(request.getHeader("DPoP")).thenReturn(dpopProof);
        }
        token.doPost(request, response);
        verify(response, org.mockito.Mockito.atLeastOnce()).setStatus(200);
        return writer.toString();
    }

    /** Builds a DPoP proof JWT per RFC 9449 §4.2. */
    private String dpopProof(String htm, String htu, String jti) {
        RSAPublicKey rsa = (RSAPublicKey) dpopKeyPair.getPublic();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String jwk = "{\"kty\":\"RSA\",\"n\":\""
                + encoder.encodeToString(rsa.getModulus().toByteArray())
                + "\",\"e\":\"" + encoder.encodeToString(rsa.getPublicExponent().toByteArray())
                + "\"}";
        String header = "{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\",\"jwk\":" + jwk + "}";
        long now = Clock.systemUTC().instant().getEpochSecond();
        JwtClaims claims = new JwtClaims();
        claims.setClaim("htm", htm);
        claims.setClaim("htu", htu);
        claims.setIssuedAt(now);
        claims.setTokenId(jti);
        String payload = new org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter()
                .toJson(claims);
        String signingContent = encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + "." + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        try {
            java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA");
            signer.initSign(dpopKeyPair.getPrivate());
            signer.update(signingContent.getBytes(StandardCharsets.UTF_8));
            return signingContent + "."
                    + encoder.encodeToString(signer.sign());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Test
    void tokenIsDpopBoundAndUserinfoRequiresMatchingProof() throws Exception {
        String proof = dpopProof("POST", TOKEN_URI, "jti-1");
        String tokenResponse = fetchAccessToken(proof);

        // the access token carries cnf.jkt (RFC 9449 §7)
        String accessToken = ((String) tokenResponse.split("\"access_token\":\"")[1])
                .split("\"")[0];
        String payload = new String(Base64.getUrlDecoder()
                .decode(accessToken.split("\\.")[1]), StandardCharsets.UTF_8);
        assertTrue(payload.contains("\"cnf\""), "DPoP-bound token must carry cnf");
        String jkt = payload.split("\"jkt\":\"")[1].split("\"")[0];

        // recompute the thumbprint independently (RFC 7638 canonical form)
        RSAPublicKey rsa = (RSAPublicKey) dpopKeyPair.getPublic();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String canonical = "{\"e\":\"" + encoder.encodeToString(rsa.getPublicExponent().toByteArray())
                + "\",\"kty\":\"RSA\",\"n\":\"" + encoder.encodeToString(rsa.getModulus().toByteArray())
                + "\"}";
        String expected = encoder.encodeToString(java.security.MessageDigest
                .getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
        assertEquals(expected, jkt, "jkt must be the RFC 7638 thumbprint of the proof key");

        // userinfo: bound token without proof -> 401
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        lenient().when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);
        lenient().when(request.getMethod()).thenReturn("GET");
        userinfo.doGet(request, response);
        verify(response).setStatus(401);
        verify(response, never()).setStatus(200);
        assertFalse(writer.toString().contains("\"sub\""));
        org.mockito.Mockito.clearInvocations(response);

        // userinfo: bound token + valid fresh proof from the bound key -> 200 with sub
        writer.getBuffer().setLength(0);
        lenient().when(request.getHeader("DPoP")).thenReturn(
                dpopProof("GET", "https://auth.example.test/userinfo", "jti-2"));
        userinfo.doGet(request, response);
        verify(response).setStatus(200);
        assertTrue(writer.toString().contains("\"sub\""));
    }

    @Test
    void mismatchedProofKeyIsRejected() throws Exception {
        // token bound to dpopKeyPair...
        String accessToken = accessTokenOf(fetchAccessToken(
                dpopProof("POST", TOKEN_URI, "jti-a")));

        // ...but the proof at userinfo comes from a different key
        java.security.KeyPairGenerator otherGen = KeyPairGenerator.getInstance("RSA");
        otherGen.initialize(2048);
        KeyPair other = otherGen.generateKeyPair();
        KeyPair original = dpopKeyPair;
        dpopKeyPair = other;
        String foreignProof = dpopProof("GET", "https://auth.example.test/userinfo", "jti-b");
        dpopKeyPair = original;

        lenient().when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);
        lenient().when(request.getHeader("DPoP")).thenReturn(foreignProof);
        lenient().when(request.getMethod()).thenReturn("GET");
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        userinfo.doGet(request, response);
        verify(response).setStatus(401);
        verify(response, never()).setStatus(200);
        assertFalse(writer.toString().contains("\"sub\""));
        org.mockito.Mockito.clearInvocations(response);
    }

    @Test
    void replayedDpopProofIsRejected() throws Exception {
        String proof = dpopProof("POST", TOKEN_URI, "same-jti");
        fetchAccessToken(proof);

        writer.getBuffer().setLength(0);
        org.mockito.Mockito.reset(response, request);
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getInputStream()).thenReturn(body("grant_type=client_credentials&scope=openid"));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
        lenient().when(request.getHeader("DPoP")).thenReturn(proof); // identical jti
        token.doPost(request, response);
        verify(response).setStatus(400);
    }

    @Test
    void corsFilterAllowsListedOriginAndHandlesPreflight() throws Exception {
        ProviderCorsFilter filter = new ProviderCorsFilter();
        jakarta.servlet.FilterConfig config = org.mockito.Mockito.mock(jakarta.servlet.FilterConfig.class);
        when(config.getInitParameter(ProviderCorsFilter.INIT_PARAM_ORIGINS))
                .thenReturn("https://spa.example.test");
        filter.init(config);

        jakarta.servlet.FilterChain chain = org.mockito.Mockito.mock(jakarta.servlet.FilterChain.class);
        when(request.getMethod()).thenReturn("OPTIONS");
        when(request.getHeader("Origin")).thenReturn("https://spa.example.test");
        filter.doFilter(request, response, chain);
        verify(response).setHeader("Access-Control-Allow-Origin", "https://spa.example.test");
        verify(response).setStatus(204);
        org.mockito.Mockito.verify(chain, org.mockito.Mockito.never()).doFilter(request, response);
    }

    @Test
    void corsFilterIgnoresUnlistedOrigin() throws Exception {
        ProviderCorsFilter filter = new ProviderCorsFilter();
        jakarta.servlet.FilterConfig config = org.mockito.Mockito.mock(jakarta.servlet.FilterConfig.class);
        when(config.getInitParameter(ProviderCorsFilter.INIT_PARAM_ORIGINS))
                .thenReturn("https://spa.example.test");
        filter.init(config);

        jakarta.servlet.FilterChain chain = org.mockito.Mockito.mock(jakarta.servlet.FilterChain.class);
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Origin")).thenReturn("https://evil.example");
        filter.doFilter(request, response, chain);
        org.mockito.Mockito.verify(response, org.mockito.Mockito.never())
                .setHeader(org.mockito.ArgumentMatchers.eq("Access-Control-Allow-Origin"),
                        org.mockito.ArgumentMatchers.anyString());
        org.mockito.Mockito.verify(chain).doFilter(request, response);
    }

    @Test
    void promptNoneRedirectsWithLoginRequired() throws Exception {
        lenient().when(request.getParameter("response_type")).thenReturn("code");
        lenient().when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
        lenient().when(request.getParameter("redirect_uri")).thenReturn("https://rp.example/cb");
        lenient().when(request.getParameter("prompt")).thenReturn("none");
        lenient().when(request.getParameter("state")).thenReturn("xyz");
        lenient().when(request.getParameter("code_challenge")).thenReturn(
                AuthorizationCodeService.s256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        lenient().when(request.getParameter("code_challenge_method")).thenReturn("S256");
        new AuthorizationEndpointServlet(server).doGet(request, response);

        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        assertTrue(location.getValue().contains("error=login_required"));
        assertTrue(location.getValue().contains("state=xyz"));
        assertTrue(location.getValue().contains("iss="));
    }

    private static String accessTokenOf(String tokenResponse) {
        return ((String) tokenResponse.split("\"access_token\":\"")[1]).split("\"")[0];
    }

    private static jakarta.servlet.ServletInputStream body(String content) {
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
