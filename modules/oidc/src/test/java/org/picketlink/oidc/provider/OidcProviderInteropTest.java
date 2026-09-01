package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.issuance.SigningKey;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * OIDC interop hardening (PL-112): ID-token at_hash/auth_time, signed request objects and
 * back-channel logout — the features relying-party libraries actually probe for.
 */
@ExtendWith(MockitoExtension.class)
class OidcProviderInteropTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String REDIRECT_URI = "https://rp.example.test/callback";
    private static final String CLIENT_ID = "rp-client";
    private static final String CLIENT_SECRET = "rp-secret";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private ManagedIssuanceServer issuanceServer;
    private OidcProviderServer server;
    private AuthorizationEndpointServlet authorize;
    private LogoutEndpointServlet logout;
    private KeyPair clientKeyPair;
    private HttpServer backchannelServer;
    private final AtomicReference<String> receivedLogoutToken = new AtomicReference<>();

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                java.nio.file.Files.createTempDirectory("plk-oidc-interop")
                        .resolve("keys.p12").toString());
        issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        clientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .jwks(jwks())
                .backchannelLogoutUrl("http://localhost:0/backchannel") // replaced below
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(
                        Map.of("alice", "wonderland")))
                .build();
        authorize = new AuthorizationEndpointServlet(server);
        logout = new LogoutEndpointServlet(server);

        backchannelServer = HttpServer.create(new InetSocketAddress(0), 0);
        backchannelServer.createContext("/backchannel", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            String form = new String(body, StandardCharsets.UTF_8);
            receivedLogoutToken.set(form.replace("logout_token=", ""));
            byte[] ok = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, ok.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(ok);
            }
        });
        backchannelServer.start();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .jwks(jwks())
                .backchannelLogoutUrl("http://localhost:"
                        + backchannelServer.getAddress().getPort() + "/backchannel")
                .build());
    }

    @AfterEach
    void tearDown() {
        if (backchannelServer != null) {
            backchannelServer.stop(0);
        }
    }

    private String jwks() {
        java.security.interfaces.RSAPublicKey rsa =
                (java.security.interfaces.RSAPublicKey) clientKeyPair.getPublic();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"client-key-1\","
                + "\"n\":\"" + encoder.encodeToString(rsa.getModulus().toByteArray())
                + "\",\"e\":\"" + encoder.encodeToString(rsa.getPublicExponent().toByteArray())
                + "\"}]}";
    }

    private void authorizePost(Map<String, String> params) throws Exception {
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        lenient().when(response.getWriter())
                .thenReturn(new java.io.PrintWriter(new java.io.StringWriter()));
        authorize.doPost(request, response);
    }

    private String authorizationCode() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid");
        params.put("nonce", "n-1");
        params.put("code_challenge", AuthorizationCodeService.s256("verifier-1"));
        params.put("code_challenge_method", "S256");
        params.put("username", "alice");
        params.put("password", "wonderland");
        authorizePost(params);
        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String redirect = location.getValue();
        return redirect.substring((REDIRECT_URI + "?code=").length(), redirect.indexOf('&'));
    }

    private Map<String, Object> exchangeCode(String code) throws Exception {
        StringBuilder body = new StringBuilder("grant_type=authorization_code&code=" + code
                + "&redirect_uri=" + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&code_verifier=verifier-1");
        when(request.getInputStream()).thenReturn(body(body.toString()));
        when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
        java.io.StringWriter writer = new java.io.StringWriter();
        when(response.getWriter()).thenReturn(new java.io.PrintWriter(writer));
        new OidcTokenEndpointServlet(server).doPost(request, response);
        verify(response).setStatus(200);
        return parseFlat(writer.toString());
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

    private static Map<String, Object> parseFlat(String json) {
        Map<String, Object> values = new LinkedHashMap<>();
        int index = 1;
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
            values.put(json.substring(keyStart + 1, keyEnd),
                    raw.startsWith("\"") ? raw.substring(1, raw.length() - 1) : Long.valueOf(raw));
            index = valueEnd;
        }
        return values;
    }

    @Test
    void idTokenCarriesAtHashAndAuthTime() throws Exception {
        Map<String, Object> tokens = exchangeCode(authorizationCode());
        String idToken = (String) tokens.get("id_token");
        String accessToken = (String) tokens.get("access_token");
        assertNotNull(idToken);
        assertNotNull(accessToken);

        String payload = new String(Base64.getUrlDecoder().decode(idToken.split("\\.")[1]),
                StandardCharsets.UTF_8);
        assertTrue(payload.contains("auth_time"), "auth_time claim required for interop");

        // at_hash = base64url(left half of SHA-256(access_token))
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(accessToken.getBytes(StandardCharsets.UTF_8));
        byte[] leftHalf = new byte[16];
        System.arraycopy(digest, 0, leftHalf, 0, 16);
        String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(leftHalf);
        assertTrue(payload.contains("\"at_hash\":\"" + expected + "\""),
                "at_hash must match OIDC Core 3.1.3.6 computation");
    }

    @Test
    void signedRequestObjectParametersTakePrecedence() throws Exception {
        // nonce only exists inside the signed request object — it must reach the ID token
        String requestObject = signedRequestObject(CLIENT_ID, ISSUER, "n-from-request-object");
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", "openid");
        params.put("request", requestObject);
        params.put("code_challenge", AuthorizationCodeService.s256("verifier-1"));
        params.put("code_challenge_method", "S256");
        params.put("username", "alice");
        params.put("password", "wonderland");
        authorizePost(params);

        org.mockito.ArgumentCaptor<String> location =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Location"), location.capture());
        String redirect = location.getValue();
        assertTrue(redirect.startsWith(REDIRECT_URI + "?code="));
        String code = redirect.substring((REDIRECT_URI + "?code=").length(), redirect.indexOf('&'));
        Map<String, Object> tokens = exchangeCode(code);
        String payload = new String(Base64.getUrlDecoder()
                .decode(((String) tokens.get("id_token")).split("\\.")[1]), StandardCharsets.UTF_8);
        assertTrue(payload.contains("n-from-request-object"),
                "request-object nonce must override query parameters");
    }

    @Test
    void unsignedRequestObjectIsRejected() throws Exception {
        String unsigned = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes())
                + "." + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString("{\"nonce\":\"x\"}".getBytes())
                + ".";
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("request", unsigned);
        authorizePost(params);
        verify(response).setStatus(400);
    }

    @Test
    void tamperedRequestObjectIsRejected() throws Exception {
        String signed = signedRequestObject(CLIENT_ID, ISSUER, "n");
        String[] parts = signed.split("\\.");
        String forged = parts[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"iss\":\"rp-client\",\"sub\":\"rp-client\",\"aud\":\"https://auth.example.test\",\"redirect_uri\":\"https://evil.example\",\"exp\":9999999999,\"jti\":\"t\"}"
                        .getBytes())
                + "." + parts[2];
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("request", forged);
        authorizePost(params);
        verify(response).setStatus(400);
    }

    @Test
    void backChannelLogoutPostsSignedLogoutToken() throws Exception {
        String idTokenHint = mintTokenForAlice();
        Map<String, String> params = new LinkedHashMap<>();
        params.put("id_token_hint", idTokenHint);
        params.put("post_logout_redirect_uri", REDIRECT_URI);
        params.forEach((name, value) -> lenient().when(request.getParameter(name)).thenReturn(value));
        lenient().when(response.getWriter())
                .thenReturn(new java.io.PrintWriter(new java.io.StringWriter()));
        logout.doGet(request, response);

        verify(response).setStatus(302);
        String logoutToken = receivedLogoutToken.get();
        assertNotNull(logoutToken, "back-channel logout_token must be posted to the client");
        String payload = new String(Base64.getUrlDecoder().decode(logoutToken.split("\\.")[1]),
                StandardCharsets.UTF_8);
        assertTrue(payload.contains("http://schemas.openid.net/event/backchannel-logout"));
        assertTrue(payload.contains("\"sub\":\"alice\""));
        assertTrue(payload.contains("\"aud\":\"" + CLIENT_ID + "\""));
    }

    private String mintTokenForAlice() {
        return issuanceServer.getIssuanceManager()
                .issue(org.picketlink.auth.oauth.issuance.IssuanceRequest
                        .forClient(issuanceServer.getClientStore().findByClientId(CLIENT_ID).get())
                        .grantType("oidc-id-token")
                        .subject("alice")
                        .build()).getTokenValue();
    }

    /** Signed request object per OIDC Core 6.1: iss/sub = client, aud = issuer. */
    private String signedRequestObject(String clientId, String audience, String nonce) {
        long now = java.time.Instant.now().getEpochSecond();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(clientId);
        claims.setSubject(clientId);
        claims.setAudience(audience);
        claims.setIssuedAt(now);
        claims.setExpiryTime(now + 300);
        claims.setTokenId("req-" + System.nanoTime());
        claims.setClaim("response_type", "code");
        claims.setClaim("redirect_uri", REDIRECT_URI);
        claims.setClaim("nonce", nonce);
        JwsHeaders headers = new JwsHeaders();
        headers.setAlgorithm("RS256");
        headers.setKeyId("client-key-1");
        return new JwsJwtCompactProducer(headers, claims).signWith(
                SigningKey.forKeyPair("client-key-1", clientKeyPair, SignatureAlgorithm.RS256)
                        .getSignatureProvider());
    }
}
