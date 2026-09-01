package org.picketlink.auth.oauth.servlet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.admin.AdminScopeFilter;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.store.IssuancePolicyConfig;
import org.picketlink.auth.oauth.store.JdbcAccessTokenRegistry;
import org.picketlink.auth.oauth.store.SigningKeyStore;
import org.picketlink.auth.oauth.token.AccessTokenGenerator;

/**
 * Plain-servlet admin API for containers without CXF (Tomcat, WildFly deployments using
 * {@link OAuthTokenEndpointServlet}). Same surface as the JAX-RS resources:
 * {@code clients}, {@code policies}, {@code keys}, {@code tokens} — every request must carry
 * a bearer JWT granting the {@code auth-admin} scope (validated through the issuance manager).
 *
 * <p>Typical mapping: {@code /api/auth/admin/*} so the element default
 * {@code api-base="../api/auth/admin"} works unchanged.
 */
public class AdminApiServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final String MASKED_SECRET = "********";

    private transient ManagedIssuanceServer server;

    public AdminApiServlet() {
    }

    public AdminApiServlet(ManagedIssuanceServer server) {
        this.server = server;
    }

    @Override
    public void init() {
        if (server == null) {
            Object configured = getServletContext().getAttribute(ManagedIssuanceServer.class.getName());
            if (configured instanceof ManagedIssuanceServer) {
                server = (ManagedIssuanceServer) configured;
            }
        }
        if (server == null) {
            throw new IllegalStateException("ManagedIssuanceServer must be configured"
                    + " (ManagedAuthServerServletContextListener)");
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!authorize(request, response)) {
            return;
        }
        String[] path = path(request);
        if (isClients(path)) {
            writeJson(response, 200, clientsJson(server.getClientStore().findAll()));
        } else if (isPolicies(path)) {
            writeJson(response, 200, server.getPolicyStore().load().toJson());
        } else if (isKeys(path) && server.isJdbcProfile()) {
            writeJson(response, 200, keysJson());
        } else if (isTokens(path)) {
            writeTokens(response);
        } else {
            notFound(response);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!authorize(request, response)) {
            return;
        }
        String[] path = path(request);
        String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (isClients(path)) {
            createClient(body, response);
        } else if (isKeys(path) && "rotate".equals(segment(path, 1))) {
            rotateKey(response);
        } else {
            notFound(response);
        }
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!authorize(request, response)) {
            return;
        }
        String[] path = path(request);
        String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (isPolicies(path)) {
            updatePolicy(body, response);
        } else if (isClients(path) && segment(path, 1) != null) {
            updateClient(segment(path, 1), body, response);
        } else if (isKeys(path) && segment(path, 1) != null && "activate".equals(segment(path, 2))) {
            activateKey(segment(path, 1), response);
        } else {
            notFound(response);
        }
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!authorize(request, response)) {
            return;
        }
        String[] path = path(request);
        if (isClients(path) && segment(path, 1) != null) {
            writeStatus(response, server.getClientStore().delete(segment(path, 1)) ? 204 : 404);
        } else if (isTokens(path) && segment(path, 1) != null && server.isJdbcProfile()) {
            JdbcAccessTokenRegistry registry = (JdbcAccessTokenRegistry) server.getTokenRegistry();
            writeStatus(response, registry.removeByTokenHash(segment(path, 1)) ? 204 : 404);
        } else {
            notFound(response);
        }
    }

    /** Bearer + auth-admin scope guard, mirroring {@link AdminScopeFilter}. */
    private boolean authorize(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            writeError(response, 401, "Admin access requires a bearer token");
            return false;
        }
        try {
            Object scope = server.getIssuanceManager().validate(authorization.substring(7).trim())
                    .getClaim(org.picketlink.auth.oauth.issuance.JwtIssuanceManager.CLAIM_SCOPE);
            if (scope == null || !Set.of(scope.toString().split(" ")).contains(AdminScopeFilter.ADMIN_SCOPE)) {
                writeError(response, 401, "Bearer token does not grant the '"
                        + AdminScopeFilter.ADMIN_SCOPE + "' scope");
                return false;
            }
            return true;
        } catch (RuntimeException ex) {
            writeError(response, 401, ex.getMessage());
            return false;
        }
    }

    private void createClient(String body, HttpServletResponse response) throws IOException {
        org.picketlink.auth.oauth.admin.JsonBody json = org.picketlink.auth.oauth.admin.JsonBody.parse(body);
        String clientId = json.string("clientId");
        if (clientId == null || clientId.isBlank()) {
            writeError(response, 400, "clientId is required");
            return;
        }
        if (server.getClientStore().findByClientId(clientId).isPresent()) {
            writeError(response, 409, "client already exists");
            return;
        }
        String secret = json.string("clientSecret");
        boolean generated = false;
        if (secret == null) {
            secret = new AccessTokenGenerator(32).generate();
            generated = true;
        }
        RegisteredClient client = buildClient(json, clientId, secret);
        server.getClientStore().save(client);
        String view = clientJson(client);
        if (generated) {
            view = view.replace("\"" + MASKED_SECRET + "\"",
                    "\"" + OAuthJsonWriter.escape(secret) + "\"");
        }
        writeJson(response, 201, view);
    }

    private void updateClient(String clientId, String body, HttpServletResponse response) throws IOException {
        Optional<RegisteredClient> existing = server.getClientStore().findByClientId(clientId);
        if (!existing.isPresent()) {
            notFound(response);
            return;
        }
        org.picketlink.auth.oauth.admin.JsonBody json = org.picketlink.auth.oauth.admin.JsonBody.parse(body);
        String secret = json.string("clientSecret");
        if (secret == null) {
            secret = existing.get().getClientSecret();
        }
        server.getClientStore().save(buildClient(json, clientId, secret));
        writeJson(response, 200, clientJson(server.getClientStore().findByClientId(clientId).get()));
    }

    private static RegisteredClient buildClient(org.picketlink.auth.oauth.admin.JsonBody json,
            String clientId, String secret) {
        RegisteredClient.Builder builder = RegisteredClient.builder(clientId, secret);
        builder.scopes(json.array("scopes"));
        String authMethod = json.string("tokenEndpointAuthMethod");
        if (authMethod != null) {
            builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.fromValue(authMethod));
        }
        Set<String> audiences = json.array("allowedAudiences");
        if (!audiences.isEmpty()) {
            builder.allowedAudiences(audiences);
        }
        String jwks = json.string("jwks");
        if (jwks != null) {
            builder.jwks(jwks);
        }
        long maxLifetime = json.number("maxTokenLifetimeSeconds", 0L);
        if (maxLifetime > 0) {
            builder.maxTokenLifetimeSeconds(maxLifetime);
        }
        return builder.build();
    }

    private void updatePolicy(String body, HttpServletResponse response) throws IOException {
        IssuancePolicyConfig config = IssuancePolicyConfig.fromJson(body);
        if (!config.getAllowedAlgorithms().contains(config.getDefaultAlgorithm())
                || config.getMaxLifetimeSeconds() <= 0
                || config.getDefaultLifetimeSeconds() <= 0
                || config.getDefaultLifetimeSeconds() > config.getMaxLifetimeSeconds()) {
            writeError(response, 400, "invalid policy configuration");
            return;
        }
        server.getPolicyStore().save(config);
        writeJson(response, 200, config.toJson());
    }

    private void rotateKey(HttpServletResponse response) throws IOException {
        SigningKeyStore keyStore = keyStore(response);
        if (keyStore == null) {
            return;
        }
        try {
            keyStore.rotate();
            writeJson(response, 200, keysJson());
        } catch (Exception ex) {
            writeError(response, 500, "key rotation failed: " + ex.getMessage());
        }
    }

    private void activateKey(String keyId, HttpServletResponse response) throws IOException {
        SigningKeyStore keyStore = keyStore(response);
        if (keyStore == null) {
            return;
        }
        try {
            keyStore.activate(keyId);
            writeStatus(response, 204);
        } catch (IllegalArgumentException ex) {
            notFound(response);
        }
    }

    private SigningKeyStore keyStore(HttpServletResponse response) throws IOException {
        if (server.isJdbcProfile()) {
            return server.getKeyStore();
        }
        writeError(response, 404, "signing key management requires the JDBC store profile");
        return null;
    }

    private void writeTokens(HttpServletResponse response) throws IOException {
        if (!server.isJdbcProfile()) {
            writeError(response, 404, "token browsing requires the JDBC store profile");
            return;
        }
        List<JdbcAccessTokenRegistry.TokenRecordView> records =
                ((JdbcAccessTokenRegistry) server.getTokenRegistry()).list(100);
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < records.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(records.get(i).toJson());
        }
        json.append(']');
        writeJson(response, 200, json.toString());
    }

    private String keysJson() {
        return server.getKeyStore().loadDocument().toJson();
    }

    private static String clientsJson(List<RegisteredClient> clients) {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < clients.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(clientJson(clients.get(i)));
        }
        json.append(']');
        return json.toString();
    }

    private static String clientJson(RegisteredClient client) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        json.append("\"clientId\":\"").append(OAuthJsonWriter.escape(client.getClientId())).append('"');
        json.append(",\"clientSecret\":\"")
                .append(client.getClientSecret() == null ? "" : MASKED_SECRET).append('"');
        json.append(",\"scopes\":[");
        int i = 0;
        for (String scope : client.getScopes()) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(OAuthJsonWriter.escape(scope)).append('"');
            i++;
        }
        json.append(']');
        json.append(",\"tokenEndpointAuthMethod\":\"")
                .append(client.getTokenEndpointAuthMethod().getValue()).append('"');
        json.append(",\"allowedAudiences\":[");
        i = 0;
        for (String audience : client.getAllowedAudiences()) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(OAuthJsonWriter.escape(audience)).append('"');
            i++;
        }
        json.append(']');
        json.append(",\"hasJwks\":").append(client.getJwks() != null);
        json.append(",\"maxTokenLifetimeSeconds\":").append(client.getMaxTokenLifetimeSeconds());
        json.append('}');
        return json.toString();
    }

    private static String[] path(HttpServletRequest request) {
        String pathInfo = request.getPathInfo();
        if (pathInfo == null || pathInfo.equals("/") || pathInfo.isEmpty()) {
            return new String[0];
        }
        return pathInfo.substring(1).split("/");
    }

    private static String segment(String[] path, int index) {
        return path.length > index ? path[index] : null;
    }

    private static boolean isClients(String[] path) {
        return path.length > 0 && "clients".equals(path[0]);
    }

    private static boolean isPolicies(String[] path) {
        return path.length == 1 && "policies".equals(path[0]);
    }

    private static boolean isKeys(String[] path) {
        return path.length > 0 && "keys".equals(path[0]);
    }

    private static boolean isTokens(String[] path) {
        return path.length == 1 && "tokens".equals(path[0]);
    }

    private static void notFound(HttpServletResponse response) throws IOException {
        writeStatus(response, 404);
    }

    private static void writeStatus(HttpServletResponse response, int status) throws IOException {
        response.setStatus(status);
    }

    private static void writeJson(HttpServletResponse response, int status, String json) throws IOException {
        response.setStatus(status);
        response.setContentType(OAuthConstants.APPLICATION_JSON);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(json);
    }

    private static void writeError(HttpServletResponse response, int status, String description)
            throws IOException {
        response.setStatus(status);
        response.setContentType(OAuthConstants.APPLICATION_JSON);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("WWW-Authenticate",
                "Bearer error=\"insufficient_scope\", error_description=\""
                        + OAuthJsonWriter.escape(description) + "\"");
        response.getWriter().write("{\"error\":\"" + OAuthJsonWriter.escape(description) + "\"}");
    }
}
