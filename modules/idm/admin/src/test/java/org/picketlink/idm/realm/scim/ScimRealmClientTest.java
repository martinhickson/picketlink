package org.picketlink.idm.realm.scim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ScimRealmClientTest {

    private HttpServer server;
    private String baseUrl;
    private final AtomicReference<String> authorization = new AtomicReference<String>();

    @BeforeEach
    void startServer() throws IOException {
        authorization.set(null);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/scim/Users", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            if ("GET".equals(exchange.getRequestMethod())) {
                writeJson(exchange, """
                        {"Resources":[{"id":"u1","userName":"alice","active":true,"groups":[{"value":"role1"}]}]}
                        """);
            } else if ("PUT".equals(exchange.getRequestMethod())) {
                writeJson(exchange, """
                        {"id":"u1","userName":"alice","active":false,"groups":[{"value":"role2"}]}
                        """);
            } else {
                exchange.sendResponseHeaders(405, -1);
                exchange.close();
            }
        });
        server.createContext("/scim/Roles", exchange -> writeJson(exchange, """
                {"Resources":[{"id":"r1","displayName":"administrator"}]}
                """));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/scim";
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void sendsBearerTokenAndListsUsers() throws Exception {
        ScimRealmClient client = new ScimRealmClient(baseUrl, "secret-token", "/Users", "/Groups", "/Roles");
        List<ScimRealmClient.ScimResource> users = client.listUsers();
        assertEquals(1, users.size());
        assertEquals("alice", users.get(0).loginName());
        assertEquals("Bearer secret-token", authorization.get());
    }

    @Test
    void updatesUserViaPut() throws Exception {
        ScimRealmClient client = new ScimRealmClient(baseUrl, "", "/Users", "/Groups", "/Roles");
        ScimRealmClient.ScimResource updated = client.updateUser("u1", null, false, List.of("role2"));
        assertEquals("u1", updated.getId());
        assertTrue(!updated.isActive());
        assertEquals("role2", updated.getGroups().get(0));
    }

    @Test
    void listsRolesExtensionResources() throws Exception {
        ScimRealmClient client = new ScimRealmClient(baseUrl, "", "/Users", "/Groups", "/Roles");
        assertEquals(List.of("administrator"), ScimRealmClient.roleNames(client.listRoles()));
    }

    private static void writeJson(com.sun.net.httpserver.HttpExchange exchange, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(body);
        }
    }
}
