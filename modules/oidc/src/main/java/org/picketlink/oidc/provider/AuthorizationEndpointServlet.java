package org.picketlink.oidc.provider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.picketlink.auth.oauth.client.store.ClientRegistrationStore;
import org.picketlink.auth.oauth.issuance.ClientAssertionValidator;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * OIDC authorization endpoint ({@code /authorize}): {@code response_type=code} with PKCE
 * (S256). GET renders a minimal login form (or the deployment's own SSO front-end can POST
 * credentials straight here); POST authenticates the subject through the configured
 * {@link SubjectAuthenticator} and redirects back with a single-use code bound to client,
 * redirect URI, subject, scopes, nonce and PKCE challenge.
 */
public class AuthorizationEndpointServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient OidcProviderServer server;
    private transient ClientAssertionValidator requestObjectValidator;

    public AuthorizationEndpointServlet() {
    }

    public AuthorizationEndpointServlet(OidcProviderServer server) {
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
        RequestParams params = validate(request, response);
        if (params == null) {
            return;
        }
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/html");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        StringBuilder html = new StringBuilder();
        html.append("<!doctype html><html><body><form method=\"post\">");
        html.append("<h3>Sign in</h3>");
        for (Map.Entry<String, String> hidden : params.hiddenFields()) {
            html.append("<input type=\"hidden\" name=\"").append(escapeHtml(hidden.getKey()))
                    .append("\" value=\"").append(escapeHtml(hidden.getValue())).append("\"/>");
        }
        html.append("<label>Username <input name=\"username\"/></label>");
        html.append("<label>Password <input name=\"password\" type=\"password\"/></label>");
        html.append("<button type=\"submit\">Sign in</button>");
        html.append("</form></body></html>");
        response.getWriter().write(html.toString());
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        RequestParams params = validate(request, response);
        if (params == null) {
            return;
        }
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        Optional<String> subject = server.getSubjectAuthenticator().authenticate(username, password);
        if (!subject.isPresent()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("text/html");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write("<p>Invalid credentials</p>");
            return;
        }
        String code = server.getAuthorizationCodes().create(
                params.clientId, params.redirectUri, subject.get(), params.scope,
                params.nonce, params.codeChallenge);
        String redirect = params.redirectUri
                + (params.redirectUri.contains("?") ? "&" : "?")
                + "code=" + code
                + "&state=" + urlEncode(params.state == null ? "" : params.state);
        response.setHeader("Location", redirect);
        response.setStatus(HttpServletResponse.SC_FOUND);
    }

    private RequestParams validate(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String responseType = request.getParameter("response_type");
        String clientId = request.getParameter("client_id");
        String redirectUri = request.getParameter("redirect_uri");
        String scope = request.getParameter("scope");
        String state = request.getParameter("state");
        String nonce = request.getParameter("nonce");
        String codeChallenge = request.getParameter("code_challenge");
        String codeChallengeMethod = request.getParameter("code_challenge_method");

        if (!"code".equals(responseType)) {
            error(response, 400, "unsupported_response_type");
            return null;
        }
        Optional<RegisteredClient> registered = store().findByClientId(clientId);
        if (!registered.isPresent()) {
            // never redirect to an unvalidated URI
            error(response, 400, "unauthorized_client");
            return null;
        }
        if (redirectUri == null || !registered.get().getAllowedRedirectUris().contains(redirectUri)) {
            error(response, 400, "invalid redirect_uri");
            return null;
        }
        if (codeChallenge != null && !"S256".equals(codeChallengeMethod)) {
            error(response, 400, "PKCE code_challenge_method must be S256");
            return null;
        }
        // prompt=none demands silent SSO, which a session-less provider cannot grant —
        // respond per OIDC Core 3.1.2.1 with the login_required error code
        String prompt = request.getParameter("prompt");
        if (prompt != null && prompt.contains("none")) {
            response.setHeader("Location", redirectUri
                    + (redirectUri.contains("?") ? "&" : "?")
                    + "error=login_required"
                    + (state == null ? "" : "&state=" + urlEncode(state)));
            response.setStatus(HttpServletResponse.SC_FOUND);
            return null;
        }
        // request objects: signed JWT authorization requests (OIDC Core 6.1/6.3). The JWT's
        // parameters take precedence over the query parameters. Unsigned request objects are
        // rejected (they carry no integrity); request_uri is not fetched (SSRF-safe).
        String requestObject = request.getParameter("request");
        if (request.getParameter("request_uri") != null) {
            error(response, 400, "request_uri not supported");
            return null;
        }
        RequestParams params =
                new RequestParams(clientId, redirectUri, scope, state, nonce, codeChallenge);
        if (requestObject != null) {
            params = applyRequestObject(requestObject, params, registered.get(), response);
        }
        return params;
    }

    /**
     * Verifies a signed request object against the client's registered JWKS (issuer/subject
     * must be the client, audience this issuer — same guarantees as RFC 7523 assertions) and
     * overlays its authorization parameters on the query parameters.
     */
    private RequestParams applyRequestObject(String requestObject, RequestParams query,
            RegisteredClient client, HttpServletResponse response) throws IOException {
        if (requestObjectValidator == null) {
            requestObjectValidator = new ClientAssertionValidator(server.getIssuer(),
                    java.time.Clock.systemUTC());
        }
        org.apache.cxf.rs.security.jose.jwt.JwtClaims claims;
        try {
            claims = requestObjectValidator.validate(requestObject, client);
        } catch (org.picketlink.auth.oauth.OAuthException ex) {
            error(response, 400, "invalid request object: " + ex.getError().getErrorDescription());
            return null;
        }
        String responseType = stringClaim(claims, "response_type");
        String redirectUri = stringClaim(claims, "redirect_uri");
        String scope = stringClaim(claims, "scope");
        String state = stringClaim(claims, "state");
        String nonce = stringClaim(claims, "nonce");
        String codeChallenge = stringClaim(claims, "code_challenge");
        if (responseType != null && !"code".equals(responseType)) {
            error(response, 400, "unsupported_response_type");
            return null;
        }
        if (redirectUri != null && !client.getAllowedRedirectUris().contains(redirectUri)) {
            error(response, 400, "invalid redirect_uri");
            return null;
        }
        // overlay: request-object values take precedence per OIDC Core 6.1
        return new RequestParams(
                query.clientId,
                redirectUri != null ? redirectUri : query.redirectUri,
                scope != null ? scope : query.scope,
                state != null ? state : query.state,
                nonce != null ? nonce : query.nonce,
                codeChallenge != null ? codeChallenge : query.codeChallenge);
    }

    private static String stringClaim(org.apache.cxf.rs.security.jose.jwt.JwtClaims claims,
            String name) {
        Object value = claims.getClaim(name);
        return value == null ? null : String.valueOf(value);
    }

    private ClientRegistrationStore store() {
        return server.getIssuanceServer().getClientStore();
    }

    private static void error(HttpServletResponse response, int status, String description)
            throws IOException {
        response.setStatus(status);
        response.setContentType("text/plain");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(description);
    }

    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Validated authorization request, replayed through the login form as hidden fields. */
    private static final class RequestParams {

        final String clientId;
        final String redirectUri;
        final String scope;
        final String state;
        final String nonce;
        final String codeChallenge;

        RequestParams(String clientId, String redirectUri, String scope, String state,
                String nonce, String codeChallenge) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.scope = scope;
            this.state = state;
            this.nonce = nonce;
            this.codeChallenge = codeChallenge;
        }

        java.util.List<Map.Entry<String, String>> hiddenFields() {
            java.util.List<Map.Entry<String, String>> fields = new java.util.ArrayList<>();
            fields.add(Map.entry("response_type", "code"));
            fields.add(Map.entry("client_id", clientId == null ? "" : clientId));
            fields.add(Map.entry("redirect_uri", redirectUri));
            if (scope != null) {
                fields.add(Map.entry("scope", scope));
            }
            if (state != null) {
                fields.add(Map.entry("state", state));
            }
            if (nonce != null) {
                fields.add(Map.entry("nonce", nonce));
            }
            if (codeChallenge != null) {
                fields.add(Map.entry("code_challenge", codeChallenge));
                fields.add(Map.entry("code_challenge_method", "S256"));
            }
            return fields;
        }
    }
}
