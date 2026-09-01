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

    private final transient String issuer;
    private final transient String basePath;

    public DiscoveryServlet(String issuer, String basePath) {
        this.issuer = issuer;
        this.basePath = normalize(basePath);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        StringBuilder json = new StringBuilder("{");
        field(json, "issuer", issuer, true);
        field(json, "authorization_endpoint", basePath + "/authorize", false);
        field(json, "pushed_authorization_request_endpoint", basePath + "/par", false);
        field(json, "token_endpoint", basePath + "/token", false);
        field(json, "userinfo_endpoint", basePath + "/userinfo", false);
        field(json, "end_session_endpoint", basePath + "/logout", false);
        field(json, "jwks_uri", basePath + "/jwks.json", false);
        field(json, "response_types_supported", "code", false);
        field(json, "grant_types_supported",
                "authorization_code refresh_token client_credentials"
                + " urn:ietf:params:oauth:grant-type:token-exchange", false);
        field(json, "subject_types_supported", "public", false);
        field(json, "id_token_signing_alg_values_supported", "RS256 ES256", false);
        field(json, "code_challenge_methods_supported", "S256", false);
        field(json, "token_endpoint_auth_methods_supported",
                "client_secret_basic client_secret_post private_key_jwt", false);
        field(json, "scopes_supported", "openid profile email", false);
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

    private static String normalize(String basePath) {
        if (basePath == null || basePath.isBlank() || "/".equals(basePath)) {
            return "";
        }
        String normalized = basePath.trim();
        return normalized.endsWith("/") ? normalized.substring(0, normalized.length() - 1) : normalized;
    }
}
