package org.picketlink.idm.admin.it.support;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class ScimMockServer {

    private static HttpServer server;
    private static String baseUrl;
    private static final List<String> usersJson = new CopyOnWriteArrayList<String>();

    private ScimMockServer() {
    }

    public static void start() throws IOException {
        if (server != null) {
            return;
        }
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
    }

    public static void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
            baseUrl = null;
        }
        usersJson.clear();
    }

    public static String baseUrl() {
        if (baseUrl == null) {
            throw new IllegalStateException("SCIM mock server is not started");
        }
        return baseUrl;
    }

    public static List<String> users() {
        return new ArrayList<String>(usersJson);
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
