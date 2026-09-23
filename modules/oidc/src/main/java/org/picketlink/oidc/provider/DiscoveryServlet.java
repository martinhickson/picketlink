package org.picketlink.oidc.provider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.picketlink.auth.oauth.json.OAuthJsonWriter;

/**
 * OIDC discovery document ({@code /.well-known/openid-configuration}) for the provider
 * mounted under one base path (e.g. {@code /oidc} → {@code /oidc/authorize}, {@code /oidc/token}...).
 */
public class DiscoveryServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient String issuer;
    private transient String basePath;

    /** Container constructor. Issuer and base path are read in {@link #init()}. */
    public DiscoveryServlet() {
    }

    public DiscoveryServlet(String issuer, String basePath) {
        this.issuer = issuer;
        this.basePath = normalize(basePath);
    }

    @Override
    public void init() {
        if (issuer == null || issuer.isBlank()) {
            Object configured = getServletContext().getAttribute(OidcProviderServer.class.getName());
            if (configured instanceof OidcProviderServer) {
                issuer = ((OidcProviderServer) configured).getIssuer();
            }
            if (issuer == null || issuer.isBlank()) {
                issuer = getServletContext().getInitParameter("issuer");
            }
        }
        if (basePath == null) {
            basePath = normalize(getInitParameter("basePath"));
        }
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("issuer is required for discovery");
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        StringBuilder json = new StringBuilder("{");
        field(json, "issuer", issuer, true);
        field(json, "authorization_endpoint", endpoint("/authorize"), false);
        field(json, "pushed_authorization_request_endpoint", endpoint("/par"), false);
        field(json, "device_authorization_endpoint", endpoint("/device_authorization"), false);
        field(json, "token_endpoint", endpoint("/token"), false);
        field(json, "userinfo_endpoint", endpoint("/userinfo"), false);
        field(json, "end_session_endpoint", endpoint("/logout"), false);
        field(json, "introspection_endpoint", endpoint("/introspect"), false);
        field(json, "revocation_endpoint", endpoint("/revoke"), false);
        field(json, "jwks_uri", endpoint("/jwks.json"), false);
        array(json, "response_types_supported", "code");
        array(json, "response_modes_supported",
                "query", "fragment", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt");
        array(json, "grant_types_supported",
                "authorization_code", "refresh_token", "password", "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "urn:ietf:params:oauth:grant-type:device_code");
        array(json, "subject_types_supported", "public");
        array(json, "id_token_signing_alg_values_supported", "RS256", "ES256");
        array(json, "dpop_signing_alg_values_supported", "RS256", "ES256");
        array(json, "code_challenge_methods_supported", "S256");
        array(json, "token_endpoint_auth_methods_supported",
                "client_secret_basic", "client_secret_post", "private_key_jwt");
        array(json, "scopes_supported", "openid", "profile", "email");
        bool(json, "authorization_response_iss_parameter_supported", true);
        json.append('}');
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(json.toString());
    }

    private static void field(StringBuilder json, String name, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":\"")
                .append(OAuthJsonWriter.escape(value)).append('"');
    }

    private static void array(StringBuilder json, String name, String... values) {
        json.append(",\"").append(OAuthJsonWriter.escape(name)).append("\":[");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(OAuthJsonWriter.escape(values[i])).append('"');
        }
        json.append(']');
    }

    private static void bool(StringBuilder json, String name, boolean value) {
        json.append(",\"").append(OAuthJsonWriter.escape(name)).append("\":").append(value);
    }

    /** OIDC discovery requires absolute endpoint URLs. A path is resolved against the issuer. */
    private String endpoint(String path) {
        String root = basePath == null ? "" : basePath;
        if (root.startsWith("https://") || root.startsWith("http://")) {
            return root + path;
        }
        String issuerRoot = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        return issuerRoot + root + path;
    }

    private static String normalize(String basePath) {
        if (basePath == null || basePath.isBlank() || "/".equals(basePath)) {
            return "";
        }
        String normalized = basePath.trim();
        return normalized.endsWith("/") ? normalized.substring(0, normalized.length() - 1) : normalized;
    }
}
