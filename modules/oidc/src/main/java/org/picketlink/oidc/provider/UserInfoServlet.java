package org.picketlink.oidc.provider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;

/**
 * OIDC UserInfo endpoint ({@code /userinfo}): bearer access token (validated through the
 * issuance manager chokepoint — signature, expiry, revocation) resolved to subject claims.
 */
public class UserInfoServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient OidcProviderServer server;

    public UserInfoServlet() {
    }

    public UserInfoServlet(OidcProviderServer server) {
        this.server = server;
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
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            error(response, 401, "bearer token required");
            return;
        }
        try {
            JwtClaims claims = server.getIssuanceServer().getIssuanceManager()
                    .validate(authorization.substring(7).trim());
            StringBuilder json = new StringBuilder("{");
            field(json, "sub", claims.getSubject(), true);
            Object scope = claims.getClaim("scope");
            if (scope != null) {
                field(json, "scope", scope.toString(), false);
            }
            Object clientId = claims.getClaim("client_id");
            if (clientId != null) {
                field(json, "client_id", clientId.toString(), false);
            }
            for (java.util.Map.Entry<String, String> entry
                    : server.getClaimSource().claimsFor(claims.getSubject()).entrySet()) {
                field(json, entry.getKey(), entry.getValue(), false);
            }
            json.append('}');
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(json.toString());
        } catch (RuntimeException ex) {
            error(response, 401, ex.getMessage());
        }
    }

    private static void field(StringBuilder json, String name, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":\"")
                .append(OAuthJsonWriter.escape(value == null ? "" : value)).append('"');
    }

    private static void error(HttpServletResponse response, int status, String description)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"error\":\"" + OAuthJsonWriter.escape(description) + "\"}");
    }
}
