package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;

@ExtendWith(MockitoExtension.class)
class ForeignClientBoundaryTest {

    private static final String ISSUER = "https://auth.example.test";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private OidcTokenEndpointServlet token;
    private StringWriter writer;

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                java.nio.file.Files.createTempDirectory("plk-boundary").resolve("k.p12").toString());
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder("owner", "owner-secret")
                .scope("read").build());
        issuanceServer.getClientStore().save(RegisteredClient.builder("other", "other-secret")
                .scope("read")
                .allowedAudience("https://billing.corp.example")
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer).build();
        token = new OidcTokenEndpointServlet(server);
        writer = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(writer));
    }

    @Test
    void anotherClientCannotSeeOrRevokeTheToken() throws Exception {
        String access = issue("owner", "owner-secret");

        org.mockito.Mockito.clearInvocations(response);
        writer.getBuffer().setLength(0);
        postManagement(ProviderTokenManagementServlet.introspection(server),
                "token=" + url(access), "other", "other-secret");
        verify(response).setStatus(200);
        assertTrue(writer.toString().contains("\"active\":false"));
        assertFalse(writer.toString().contains("owner"));

        org.mockito.Mockito.clearInvocations(response);
        writer.getBuffer().setLength(0);
        postManagement(ProviderTokenManagementServlet.revocation(server),
                "token=" + url(access), "other", "other-secret");
        verify(response).setStatus(400);
        assertTrue(writer.toString().contains("unauthorized_client"));
        assertTrue(server.getIssuanceServer().getIssuanceManager().validate(access) != null);
    }

    @Test
    void pinnedClientCannotExchangeForADifferentAudience() throws Exception {
        String access = issue("owner", "owner-secret");
        org.mockito.Mockito.clearInvocations(response);
        writer.getBuffer().setLength(0);
        postToken("grant_type=" + url("urn:ietf:params:oauth:grant-type:token-exchange")
                + "&subject_token=" + url(access)
                + "&subject_token_type=" + url("urn:ietf:params:oauth:token-type:access_token")
                + "&audience=" + url("https://other.corp.example"),
                "other", "other-secret");
        verify(response).setStatus(400);
        assertTrue(writer.toString().contains("audience"));
    }

    private String issue(String clientId, String secret) throws Exception {
        writer.getBuffer().setLength(0);
        postToken("grant_type=client_credentials&scope=read", clientId, secret);
        verify(response).setStatus(200);
        return writer.toString().split("\"access_token\":\"")[1].split("\"")[0];
    }

    private void postToken(String body, String clientId, String secret) throws Exception {
        when(request.getInputStream()).thenReturn(stream(body));
        lenient().when(request.getHeader("Authorization")).thenReturn(basic(clientId, secret));
        token.doPost(request, response);
    }

    private void postManagement(ProviderTokenManagementServlet servlet, String body,
            String clientId, String secret) throws Exception {
        when(request.getInputStream()).thenReturn(stream(body));
        lenient().when(request.getHeader("Authorization")).thenReturn(basic(clientId, secret));
        servlet.doPost(request, response);
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static String url(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static jakarta.servlet.ServletInputStream stream(String content) {
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
