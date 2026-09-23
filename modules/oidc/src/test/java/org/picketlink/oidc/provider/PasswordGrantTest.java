package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.io.IOException;
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
import org.picketlink.auth.oauth.issuance.RsaJwtSigningService;
import org.picketlink.auth.oauth.jwt.JwtAccessTokenValidator;
import org.picketlink.auth.oauth.jwt.JwtSettings;
import org.picketlink.auth.oauth.jwt.RsaJwtSigner;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.servlet.NextTokenPostFault;

@ExtendWith(MockitoExtension.class)
class PasswordGrantTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String CLIENT_ID = "rda-client";
    private static final String CLIENT_SECRET = "rda-secret";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private OidcTokenEndpointServlet token;
    private RsaJwtSigner signer;
    private StringWriter writer;

    @BeforeEach
    void setUp() throws Exception {
        signer = new RsaJwtSigner("shared-1");
        ManagedIssuanceServer issuance = ManagedIssuanceServer.builder(ISSUER)
                .signingService(new RsaJwtSigningService(ISSUER, signer))
                .build();
        issuance.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .scope("profile")
                .redirectUri("https://rp.example.test/callback")
                .build());
        Map<String, String> users = new LinkedHashMap<>();
        users.put("alice", "wonderland");
        AuthorizationCodeService codes = new AuthorizationCodeService(java.time.Clock.systemUTC());
        server = OidcProviderServer.builder(ISSUER, issuance)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(users))
                .authorizationCodes(codes)
                .build();
        token = new OidcTokenEndpointServlet(server);
        writer = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(writer));
    }

    @Test
    void passwordGrantIssuesTokensSignedByTheSharedKey() throws Exception {
        post("grant_type=password&username=alice&password=wonderland&scope=openid");
        String json = writer.toString();
        assertTrue(json.contains("\"access_token\""));
        assertTrue(json.contains("\"refresh_token\""));
        assertTrue(json.contains("\"id_token\""));
        String accessToken = json.split("\"access_token\":\"")[1].split("\"")[0];
        JwtAccessTokenValidator validator = new JwtAccessTokenValidator(
                new JwtSettings(ISSUER, "unused", 3600L),
                JwtAccessTokenValidator.Clock.SYSTEM,
                signer);
        assertEquals(CLIENT_ID, validator.validate(accessToken).getClientId());
        assertTrue(server.getIssuanceServer().getSigningService().publicJwksJson().contains("shared-1"));
    }

    @Test
    void passwordGrantWithoutOpenidDoesNotIssueAnIdToken() throws Exception {
        post("grant_type=password&username=alice&password=wonderland&scope=profile");
        String json = writer.toString();
        assertTrue(json.contains("\"access_token\""));
        assertTrue(!json.contains("\"id_token\""));
    }

    @Test
    void passwordGrantRejectsABadPassword() throws Exception {
        post("grant_type=password&username=alice&password=wrong");
        org.mockito.Mockito.verify(response).setStatus(400);
        assertTrue(writer.toString().contains("invalid_grant"));
    }

    @Test
    void discoveryListsThePasswordGrant() throws Exception {
        writer.getBuffer().setLength(0);
        new DiscoveryServlet(ISSUER, "/oidc").doGet(request, response);
        String json = writer.toString();
        assertTrue(json.contains("password"));
        assertTrue(json.contains("refresh_token"));
        assertTrue(json.contains("authorization_code"));
        assertTrue(json.contains("\"jwks_uri\":\"" + ISSUER + "/oidc/jwks.json\""));
        assertTrue(json.contains("\"token_endpoint\":\"" + ISSUER + "/oidc/token\""));
    }

    @Test
    void twoProvidersShareOneAuthorizationCode() {
        OidcProviderServer other = OidcProviderServer.builder(ISSUER, server.getIssuanceServer())
                .subjectAuthenticator(server.getSubjectAuthenticator())
                .authorizationCodes(server.getAuthorizationCodes())
                .build();
        String verifier = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        String code = server.getAuthorizationCodes().create(
                CLIENT_ID, "https://rp.example.test/callback", "alice", "openid", "n",
                AuthorizationCodeService.s256(verifier));
        Optional<AuthorizationCodeService.PendingCode> consumed =
                other.getAuthorizationCodes().consume(code, verifier);
        assertTrue(consumed.isPresent());
        assertEquals("alice", consumed.get().getSubject());
        assertTrue(server.getAuthorizationCodes().consume(code, verifier).isEmpty());
    }

    @Test
    void armedFaultClosesTheNextTokenPostOnly() throws Exception {
        NextTokenPostFault fault = new NextTokenPostFault();
        fault.arm();
        OidcTokenEndpointServlet faulting = new OidcTokenEndpointServlet(server, fault);
        when(request.getInputStream()).thenReturn(body(
                "grant_type=password&username=alice&password=wonderland"));
        lenient().when(request.getHeader("Authorization")).thenReturn(basic());
        IOException closed = assertThrows(IOException.class, () -> faulting.doPost(request, response));
        assertTrue(closed.getMessage().contains("Connection closed"));

        writer.getBuffer().setLength(0);
        when(request.getInputStream()).thenReturn(body(
                "grant_type=password&username=alice&password=wonderland"));
        faulting.doPost(request, response);
        org.mockito.Mockito.verify(response).setStatus(HttpServletResponse.SC_OK);
    }

    private void post(String form) throws Exception {
        when(request.getInputStream()).thenReturn(body(form));
        lenient().when(request.getHeader("Authorization")).thenReturn(basic());
        token.doPost(request, response);
    }

    private static String basic() {
        return "Basic " + java.util.Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
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
