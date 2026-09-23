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
                params.nonce, params.codeChallenge, params.maxAge);
        emitAuthorizationResponse(params, code, response);
    }

    private RequestParams validate(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String clientId = request.getParameter("client_id");
        Optional<RegisteredClient> registered = store().findByClientId(clientId);
        if (!registered.isPresent()) {
            // never redirect to an unvalidated URI
            error(response, 400, "unauthorized_client");
            return null;
        }

        // RFC 9126: request_uri values pushed by this provider's PAR endpoint are consumed
        // here (single use, client-bound) and become the effective authorization parameters;
        // external request_uri values are never fetched (SSRF-safe)
        String requestUri = request.getParameter("request_uri");
        final java.util.Map<String, String> pushedParams;
        if (requestUri != null) {
            pushedParams = server.getPushedAuthorizationRequests().consume(requestUri, clientId);
            if (pushedParams == null) {
                error(response, 400, "invalid or expired request_uri");
                return null;
            }
        } else {
            pushedParams = null;
        }

        java.util.function.BiFunction<String, String, String> pick =
                (name, fallback) -> pushedParams != null && pushedParams.containsKey(name)
                        ? pushedParams.get(name) : fallback;

        String responseType = pick.apply("response_type", request.getParameter("response_type"));
        String redirectUri = pick.apply("redirect_uri", request.getParameter("redirect_uri"));
        String scope = pick.apply("scope", request.getParameter("scope"));
        String state = pick.apply("state", request.getParameter("state"));
        String nonce = pick.apply("nonce", request.getParameter("nonce"));
        String codeChallenge = pick.apply("code_challenge", request.getParameter("code_challenge"));
        String codeChallengeMethod = pick.apply("code_challenge_method",
                request.getParameter("code_challenge_method"));
        String responseMode = pick.apply("response_mode", request.getParameter("response_mode"));
        if (responseMode != null && !SUPPORTED_RESPONSE_MODES.contains(responseMode)) {
            error(response, 400, "unsupported response_mode");
            return null;
        }

        if (!"code".equals(responseType)) {
            error(response, 400, "unsupported_response_type");
            return null;
        }
        if (redirectUri == null || !registered.get().getAllowedRedirectUris().contains(redirectUri)) {
            error(response, 400, "invalid redirect_uri");
            return null;
        }
        String requestObject = pick.apply("request", request.getParameter("request"));
        if (requestObject == null
                && !AuthorizationCodeService.s256ChallengeAccepted(codeChallenge, codeChallengeMethod)) {
            error(response, 400, "PKCE S256 is required");
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
        RequestParams params = new RequestParams(clientId, redirectUri, scope, state, nonce,
                codeChallenge, maxAge(request), responseMode);
        if (requestObject != null) {
            params = applyRequestObject(requestObject, params, codeChallengeMethod,
                    registered.get(), response);
        }
        return params;
    }

    /**
     * Verifies a signed request object against the client's registered JWKS (issuer/subject
     * must be the client, audience this issuer — same guarantees as RFC 7523 assertions) and
     * overlays its authorization parameters on the query parameters.
     */
    private RequestParams applyRequestObject(String requestObject, RequestParams query,
            String queryChallengeMethod, RegisteredClient client, HttpServletResponse response)
            throws IOException {
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
        String codeChallengeMethod = stringClaim(claims, "code_challenge_method");
        if (responseType != null && !"code".equals(responseType)) {
            error(response, 400, "unsupported_response_type");
            return null;
        }
        if (redirectUri != null && !client.getAllowedRedirectUris().contains(redirectUri)) {
            error(response, 400, "invalid redirect_uri");
            return null;
        }
        String effectiveChallenge = codeChallenge != null ? codeChallenge : query.codeChallenge;
        String effectiveMethod = codeChallengeMethod != null ? codeChallengeMethod : queryChallengeMethod;
        if (!AuthorizationCodeService.s256ChallengeAccepted(effectiveChallenge, effectiveMethod)) {
            error(response, 400, "PKCE S256 is required");
            return null;
        }
        // overlay: request-object values take precedence per OIDC Core 6.1
        return new RequestParams(
                query.clientId,
                redirectUri != null ? redirectUri : query.redirectUri,
                scope != null ? scope : query.scope,
                state != null ? state : query.state,
                nonce != null ? nonce : query.nonce,
                effectiveChallenge,
                query.maxAge,
                query.responseMode);
    }

    /** Parses the optional OIDC max_age request parameter (seconds since authentication). */
    private static Long maxAge(HttpServletRequest request) {
        String raw = request.getParameter("max_age");
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            long value = Long.parseLong(raw.trim());
            return value >= 0 ? value : null;
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private static Long parseLong(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException ex) {
            return null;
        }
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

    private static final java.util.Set<String> SUPPORTED_RESPONSE_MODES = java.util.Set.of(
            "query", "fragment", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt");

    /**
     * Emits the authorization response per the requested response_mode: query (default),
     * fragment, form_post, or the JARM modes (RFC 9101) where the response parameters are
     * wrapped in a signed JWT (iss, aud = client, short exp) as the {@code response}
     * parameter. Every redirect response carries the RFC 9207 {@code iss} parameter —
     * the authorization-response mix-up mitigation.
     */
    private void emitAuthorizationResponse(RequestParams params, String code,
            HttpServletResponse response) throws IOException {
        String state = params.state == null ? "" : params.state;
        String mode = params.responseMode == null ? "query" : params.responseMode;
        if ("form_post".equals(mode)) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("text/html");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(formPost(params.redirectUri,
                    hidden("code", code), hidden("state", state),
                    hidden("iss", server.getIssuer())));
            return;
        }
        if (mode.endsWith(".jwt") || "jwt".equals(mode)) {
            String responseJwt = jarmResponse(params, code, state);
            boolean fragment = "fragment".equals(mode) || "jwt".equals(mode);
            String separator = fragment ? "#"
                    : (params.redirectUri.contains("?") ? "&" : "?");
            String redirect = params.redirectUri + separator + "response=" + urlEncode(responseJwt);
            response.setHeader("Location", redirect);
            response.setStatus(HttpServletResponse.SC_FOUND);
            return;
        }
        String redirect = params.redirectUri
                + ("fragment".equals(mode)
                        ? "#" + "code=" + code + "&state=" + urlEncode(state)
                          + "&iss=" + urlEncode(server.getIssuer())
                        : (params.redirectUri.contains("?") ? "&" : "?")
                          + "code=" + code
                          + "&state=" + urlEncode(state)
                          + "&iss=" + urlEncode(server.getIssuer()));
        response.setHeader("Location", redirect);
        response.setStatus(HttpServletResponse.SC_FOUND);
    }

    /** JARM (RFC 9101): signed response JWT with iss, aud, short-lived exp, code and state. */
    private String jarmResponse(RequestParams params, String code, String state) {
        long now = java.time.Clock.systemUTC().instant().getEpochSecond();
        org.apache.cxf.rs.security.jose.jwt.JwtClaims claims =
                new org.apache.cxf.rs.security.jose.jwt.JwtClaims();
        claims.setIssuer(server.getIssuer());
        claims.setAudience(params.clientId);
        claims.setIssuedAt(now);
        claims.setExpiryTime(now + 120);
        claims.setClaim("code", code);
        if (state != null && !state.isBlank()) {
            claims.setClaim("state", state);
        }
        return server.getIssuanceServer().getSigningService().sign(claims, null);
    }

    private static String hidden(String name, String value) {
        return "<input type=\"hidden\" name=\"" + escapeHtml(name)
                + "\" value=\"" + escapeHtml(value) + "\"/>";
    }

    private static String formPost(String action, String... fields) {
        StringBuilder html = new StringBuilder("<!doctype html><html><body onload=\"document.forms[0].submit()\">");
        html.append("<form method=\"post\" action=\"").append(escapeHtml(action)).append("\">");
        for (String field : fields) {
            html.append(field);
        }
        html.append("</form></body></html>");
        return html.toString();
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
        final Long maxAge;
        final String responseMode;

        RequestParams(String clientId, String redirectUri, String scope, String state,
                String nonce, String codeChallenge, Long maxAge, String responseMode) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.scope = scope;
            this.state = state;
            this.nonce = nonce;
            this.codeChallenge = codeChallenge;
            this.maxAge = maxAge;
            this.responseMode = responseMode;
        }

        java.util.List<Map.Entry<String, String>> hiddenFields() {
            java.util.List<Map.Entry<String, String>> fields = new java.util.ArrayList<>();
            fields.add(Map.entry("response_type", "code"));
            fields.add(Map.entry("client_id", clientId == null ? "" : clientId));
            fields.add(Map.entry("redirect_uri", redirectUri));
            if (scope != null) {
                fields.add(Map.entry("scope", scope));
            }
            if (maxAge != null) {
                fields.add(Map.entry("max_age", String.valueOf(maxAge)));
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
