package org.picketlink.oidc.provider;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientAuthentication;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.store.PersistingClientRegistry;
import org.picketlink.auth.oauth.http.FormParameters;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.service.TokenIntrospectionService;

/**
 * Provider-side token management: RFC 7662 introspection ({@code GET/POST /introspect}) and
 * RFC 7009 revocation ({@code POST /revoke}) over tokens issued by this provider — both
 * requiring an authenticated client, both delegating to the shared services so the
 * revocation registry, validation chokepoint and audit semantics are identical to the
 * auth-module endpoints.
 */
public class ProviderTokenManagementServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final String MODE_INTROSPECT = "introspect";
    private static final String MODE_REVOKE = "revoke";

    private transient OidcProviderServer server;
    private transient ClientCredentialsAuthenticator authenticator;
    private final transient String mode;

    public ProviderTokenManagementServlet() {
        // servlet-container instantiation: mode from servlet name
        this(null, null);
    }

    private ProviderTokenManagementServlet(String mode, OidcProviderServer server) {
        this.mode = mode;
        this.server = server;
        if (server != null) {
            this.authenticator = new ClientCredentialsAuthenticator(
                    new PersistingClientRegistry(server.getIssuanceServer().getClientStore()),
                    new ConstantTimeClientSecretMatcher());
        }
    }

    /** Factory for the RFC 7662 endpoint. */
    public static ProviderTokenManagementServlet introspection(OidcProviderServer server) {
        return new ProviderTokenManagementServlet(MODE_INTROSPECT, server);
    }

    /** Factory for the RFC 7009 endpoint. */
    public static ProviderTokenManagementServlet revocation(OidcProviderServer server) {
        return new ProviderTokenManagementServlet(MODE_REVOKE, server);
    }

    @Override
    public void init() {
        if (server == null) {
            Object configured = getServletContext().getAttribute(OidcProviderServer.class.getName());
            if (configured instanceof OidcProviderServer) {
                server = (OidcProviderServer) configured;
            }
        }
        if (server == null) {
            throw new IllegalStateException("OidcProviderServer must be configured");
        }
        authenticator = newAuthenticator();
    }

    private ClientCredentialsAuthenticator newAuthenticator() {
        return new ClientCredentialsAuthenticator(
                new PersistingClientRegistry(server.getIssuanceServer().getClientStore()),
                new ConstantTimeClientSecretMatcher());
    }

    private String resolvedMode() {
        return mode != null ? mode
                : (getServletName() != null && getServletName().toLowerCase().contains("revoke")
                        ? MODE_REVOKE : MODE_INTROSPECT);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try (InputStream in = request.getInputStream()) {
            Map<String, String> form = FormParameters.parse(
                    new String(in.readAllBytes(), StandardCharsets.UTF_8));
            // RFC 7662/7009 call the parameter "token"; the shared services read
            // "access_token" — normalize before the request snapshot is built
            String token = form.get("token");
            if (token == null || token.isBlank()) {
                writeError(response, 400, "token is required");
                return;
            }
            form.put(OAuthConstants.ACCESS_TOKEN, token);
            TokenRequest tokenRequest = TokenRequest.builder()
                    .grantType(form.get(OAuthConstants.GRANT_TYPE))
                    .scope(form.get(OAuthConstants.SCOPE))
                    .authorizationHeader(request.getHeader("Authorization"))
                    .formParameters(form)
                    .build();
            ClientAuthentication authentication = authenticator.authenticate(tokenRequest);
            if (MODE_REVOKE.equals(resolvedMode())) {
                String clientId = authentication.getClient().getClientId();
                server.getIssuanceServer().getIssuanceManager().revoke(token, clientId);
                server.getRefreshTokens().revoke(token, clientId);
                response.setStatus(HttpServletResponse.SC_OK);
                return;
            }
            String json = new TokenIntrospectionService(authenticator,
                    server.getIssuanceServer().getIssuanceManager()).introspect(tokenRequest);
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(OAuthConstants.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(json);
        } catch (OAuthException ex) {
            writeError(response, ex.getHttpStatus(), ex.getError().getErrorDescription());
        }
    }

    private static void writeError(HttpServletResponse response, int status, String description)
            throws IOException {
        response.setStatus(status);
        response.setContentType(OAuthConstants.APPLICATION_JSON);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"error\":\"" + OAuthJsonWriter.escape(description) + "\"}");
    }
}
