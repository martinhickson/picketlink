package org.picketlink.idm.realm.scim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.idm.document.IdmDocumentStores;
import org.picketlink.idm.realm.IdmRealmBackends;
import org.picketlink.idm.realm.IdmRealmProviderConfig;
import org.picketlink.idm.realm.IdmRealmSnapshot;

class ScimIdmRealmBackendTest {

    private HttpServer server;
    private String baseUrl;
    private final List<String> usersJson = new ArrayList<String>();

    @BeforeEach
    void startServer() throws IOException {
        usersJson.clear();
        usersJson.add("""
                {"id":"u1","userName":"alice","active":true,"groups":[{"value":"role1"}]}
                """);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/scim/Users", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                writeJson(exchange, "{\"Resources\":[" + String.join(",", usersJson) + "]}");
            } else if ("POST".equals(exchange.getRequestMethod())) {
                usersJson.add("""
                        {"id":"u2","userName":"bob","active":true,"groups":[{"value":"role2"}]}
                        """);
                writeJson(exchange, usersJson.get(usersJson.size() - 1));
            } else if ("DELETE".equals(exchange.getRequestMethod())) {
                String path = exchange.getRequestURI().getPath();
                String userId = path.substring(path.lastIndexOf('/') + 1);
                usersJson.removeIf(entry -> entry.contains("\"id\":\"" + userId + "\""));
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
            } else {
                exchange.sendResponseHeaders(405, -1);
                exchange.close();
            }
        });
        server.createContext("/scim/Groups", exchange -> writeJson(exchange, """
                {"Resources":[{"id":"g1","displayName":"developers"}]}
                """));
        server.createContext("/scim/Roles", exchange -> writeJson(exchange, """
                {"Resources":[{"id":"r1","displayName":"administrator"}]}
                """));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/scim";
        System.setProperty(IdmRealmProviderConfig.PROVIDER_PROPERTY, IdmRealmProviderConfig.PROVIDER_SCIM);
        System.setProperty(IdmRealmProviderConfig.SCIM_BASE_URL_PROPERTY, baseUrl);
        System.setProperty(IdmRealmProviderConfig.SCIM_SYNC_TO_DOCUMENT_PROPERTY, "false");
        IdmRealmBackends.resetForTests();
        IdmDocumentStores.resetForTests();
        org.picketlink.idm.realm.config.IdmRealmConfigStores.resetForTests();
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
        System.clearProperty(IdmRealmProviderConfig.PROVIDER_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_BASE_URL_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_SYNC_TO_DOCUMENT_PROPERTY);
        IdmRealmBackends.resetForTests();
        IdmDocumentStores.resetForTests();
        org.picketlink.idm.realm.config.IdmRealmConfigStores.resetForTests();
    }

    @Test
    void loadsUsersGroupsAndRolesFromScim() throws Exception {
        IdmRealmSnapshot snapshot = IdmRealmBackends.globalBackend().loadRealm(IdmDocumentStores.DEFAULT_DOCUMENT_ID);
        assertEquals(IdmRealmProviderConfig.PROVIDER_SCIM, snapshot.getProvider());
        assertEquals(baseUrl, snapshot.getScimBaseUrl());
        assertEquals(1, snapshot.getUsers().size());
        assertEquals("alice", snapshot.getUsers().get(0).getLoginName());
        assertTrue(snapshot.getRoles().contains("administrator"));
        assertTrue(snapshot.getGroups().contains("developers"));
    }

    @Test
    void createsAndDeletesUsersThroughScim() throws Exception {
        var backend = IdmRealmBackends.globalBackend();
        IdmRealmSnapshot created = backend.createUser(
                IdmDocumentStores.DEFAULT_DOCUMENT_ID, 0L, "bob", "secret", java.util.List.of("role2"));
        assertEquals(2, created.getUsers().size());
        backend.deleteUser(IdmDocumentStores.DEFAULT_DOCUMENT_ID, 0L, "u1");
        IdmRealmSnapshot reloaded = backend.loadRealm(IdmDocumentStores.DEFAULT_DOCUMENT_ID);
        assertEquals(1, reloaded.getUsers().size());
        assertEquals("bob", reloaded.getUsers().get(0).getLoginName());
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
