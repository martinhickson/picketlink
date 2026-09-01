package org.picketlink.auth.oauth.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.StringWriter;
import java.nio.file.Path;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.picketlink.auth.oauth.admin.AdminScopeFilter;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.store.DriverManagerConnectionSource;

/** Auth matrix + CRUD through the plain-servlet admin API (SQLite-backed). */
@ExtendWith(MockitoExtension.class)
class AdminApiServletTest {

    private static final String ISSUER = "https://auth.example.test";

    @TempDir
    Path tempDir;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private ManagedIssuanceServer server;
    private AdminApiServlet servlet;
    private StringWriter responseWriter;

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                tempDir.resolve("keys.p12").toString());
        server = ManagedIssuanceServer.builder(ISSUER)
                .connectionSource(new DriverManagerConnectionSource(
                        "jdbc:sqlite:" + tempDir.resolve("admin-servlet.db"), null, null))
                .build();
        servlet = new AdminApiServlet(server);
        responseWriter = new StringWriter();
    }

    private String adminSecret() {
        Optional<RegisteredClient> admin = server.getClientStore()
                .findByClientId(ManagedIssuanceServer.ADMIN_CLIENT_ID);
        assertTrue(admin.isPresent());
        return admin.get().getClientSecret();
    }

    private String mintToken(String clientId, String clientSecret) {
        TokenResponse response = server.getTokenService().issueToken(TokenRequest.builder()
                .grantType("client_credentials")
                .authorizationHeader("Basic " + java.util.Base64.getEncoder()
                        .encodeToString((clientId + ":" + clientSecret).getBytes()))
                .build());
        return response.getAccessToken();
    }

    private void get(String path, String token) throws Exception {
        org.mockito.Mockito.lenient().when(request.getPathInfo()).thenReturn(path);
        org.mockito.Mockito.lenient().when(request.getHeader("Authorization"))
                .thenReturn(token == null ? null : "Bearer " + token);
        org.mockito.Mockito.lenient().when(response.getWriter())
                .thenReturn(new java.io.PrintWriter(responseWriter));
        servlet.doGet(request, response);
    }

    @Test
    void shouldRejectRequestsBearingNoToken() throws Exception {
        get("/clients", null);
        verifyStatus(401);
        assertTrue(responseWriter.toString().contains("bearer token"));
    }

    @Test
    void shouldRejectTokensWithoutAdminScope() throws Exception {
        // a plain client (not the seeded admin) has no auth-admin scope
        server.getClientStore().save(RegisteredClient.builder("plain-client", "plain-secret").build());
        String plainToken = mintToken("plain-client", "plain-secret");
        get("/clients", plainToken);
        verifyStatus(401);
        assertTrue(responseWriter.toString().contains(AdminScopeFilter.ADMIN_SCOPE));
    }

    @Test
    void shouldRejectGarbageTokens() throws Exception {
        get("/clients", "not-a-jwt");
        verifyStatus(401);
    }

    @Test
    void shouldListAndCreateClientsWithAdminToken() throws Exception {
        String adminToken = mintToken(ManagedIssuanceServer.ADMIN_CLIENT_ID, adminSecret());

        get("/clients", adminToken);
        verifyStatus(200);
        assertTrue(responseWriter.toString().contains(ManagedIssuanceServer.ADMIN_CLIENT_ID));

        // create a client with audience pinning
        when(request.getPathInfo()).thenReturn("/clients");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + adminToken);
        when(request.getInputStream()).thenReturn(body(
                "{\"clientId\":\"api-client\",\"scopes\":[\"read\"],"
                        + "\"allowedAudiences\":[\"https://api.example.test\"],"
                        + "\"maxTokenLifetimeSeconds\":120}"));
        when(response.getWriter()).thenReturn(new java.io.PrintWriter(responseWriter = new StringWriter()));
        servlet.doPost(request, response);
        verifyStatus(201);
        String created = responseWriter.toString();
        assertTrue(created.contains("api-client"));
        // generated secret is returned exactly once
        assertFalse(created.contains("********"));
        assertTrue(server.getClientStore().findByClientId("api-client").isPresent());
        assertEquals(java.util.Set.of("https://api.example.test"),
                server.getClientStore().findByClientId("api-client").get().getAllowedAudiences());
    }

    @Test
    void shouldDeleteClientsWithAdminToken() throws Exception {
        String adminToken = mintToken(ManagedIssuanceServer.ADMIN_CLIENT_ID, adminSecret());
        server.getClientStore().save(RegisteredClient.builder("doomed", "secret").build());

        when(request.getPathInfo()).thenReturn("/clients/doomed");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + adminToken);
        servlet.doDelete(request, response);
        verifyStatus(204);
        assertFalse(server.getClientStore().findByClientId("doomed").isPresent());
    }

    @Test
    void shouldServePoliciesWithAdminToken() throws Exception {
        String adminToken = mintToken(ManagedIssuanceServer.ADMIN_CLIENT_ID, adminSecret());
        get("/policies", adminToken);
        verifyStatus(200);
        assertTrue(responseWriter.toString().contains("allowedAlgorithms"));
    }

    private void verifyStatus(int expected) {
        org.mockito.Mockito.verify(response).setStatus(expected);
    }

    private static jakarta.servlet.ServletInputStream body(String content) {
        byte[] bytes = content.getBytes(java.nio.charset.StandardCharsets.UTF_8);
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
