package org.picketlink.oidc.provider;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.client.store.ClientRegistrationStore;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * OIDC RP-initiated logout ({@code /logout}). Accepts {@code id_token_hint} (validated through
 * the issuance manager chokepoint — signature, issuer, expiry, revocation), optional
 * {@code client_id} (must match the ID token's {@code azp}/{@code client_id}), optional
 * {@code post_logout_redirect_uri} (must be a registered redirect URI of that client, per the
 * spec's requirement that only registered URIs are honored) and {@code state} (echoed).
 * Without a valid registered post-logout redirect, renders a plain confirmation page — never
 * an open redirector.
 */
public class LogoutEndpointServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient OidcProviderServer server;

    public LogoutEndpointServlet() {
    }

    public LogoutEndpointServlet(OidcProviderServer server) {
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
        handle(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        handle(request, response);
    }

    private void handle(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String idTokenHint = request.getParameter("id_token_hint");
        String clientId = request.getParameter("client_id");
        String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");
        String state = request.getParameter("state");

        String tokenClientId = null;
        if (idTokenHint != null) {
            try {
                tokenClientId = String.valueOf(server.getIssuanceServer().getIssuanceManager()
                        .validate(idTokenHint).getClaim(
                                org.picketlink.auth.oauth.issuance.JwtIssuanceManager.CLAIM_AZP));
            } catch (RuntimeException ex) {
                // invalid hint: no redirect trust, fall through to confirmation page
            }
        }

        if (clientId == null) {
            clientId = tokenClientId;
        }
        String redirect = resolveRedirect(clientId, postLogoutRedirectUri, tokenClientId);
        if (redirect == null) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("text/html");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write("<!doctype html><html><body><p>Signed out.</p></body></html>");
            return;
        }
        if (state != null && !state.isBlank()) {
            redirect += (redirect.contains("?") ? "&" : "?") + "state="
                    + java.net.URLEncoder.encode(state, StandardCharsets.UTF_8);
        }
        notifyBackChannelLogout(clientId, tokenClientId, idTokenHint);
        response.setHeader("Location", redirect);
        response.setStatus(HttpServletResponse.SC_FOUND);
    }

    /**
     * OIDC Back-Channel Logout 1.0: when the client being logged out has a registered
     * callback URL, POST a signed logout_token (events claim per the spec, no nonce) to it.
     * Best-effort: callback failures never block the front-channel logout.
     */
    private void notifyBackChannelLogout(String clientId, String tokenClientId, String idTokenHint) {
        if (clientId == null || tokenClientId == null || !clientId.equals(tokenClientId)) {
            return;
        }
        ClientRegistrationStore store = server.getIssuanceServer().getClientStore();
        Optional<RegisteredClient> registered = store.findByClientId(clientId);
        if (!registered.isPresent() || registered.get().getBackchannelLogoutUrl() == null) {
            return;
        }
        String subject = null;
        try {
            subject = String.valueOf(server.getIssuanceServer().getIssuanceManager()
                    .validate(idTokenHint).getSubject());
        } catch (RuntimeException ex) {
            return; // no usable hint, no logout token
        }
        try {
            String logoutToken = server.getIssuanceServer().getSigningService()
                    .sign(logoutTokenClaims(clientId, subject), null);
            HttpRequest request = HttpRequest.newBuilder(URI.create(registered.get().getBackchannelLogoutUrl()))
                    .timeout(java.time.Duration.ofSeconds(5))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "logout_token=" + java.net.URLEncoder.encode(logoutToken, StandardCharsets.UTF_8)))
                    .build();
            HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception ex) {
            // best-effort: front-channel logout proceeds regardless of callback outcome
        }
    }

    private JwtClaims logoutTokenClaims(String clientId, String subject) {
        long now = server.getClock().instant().getEpochSecond();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(server.getIssuer());
        claims.setSubject(subject);
        claims.setAudience(clientId);
        claims.setIssuedAt(now);
        claims.setExpiryTime(now + 120);
        claims.setTokenId(java.util.UUID.randomUUID().toString());
        Map<String, Object> events = new LinkedHashMap<>();
        events.put("http://schemas.openid.net/event/backchannel-logout", new LinkedHashMap<>());
        claims.setClaim("events", events);
        return claims;
    }

    private String resolveRedirect(String clientId, String postLogoutRedirectUri, String tokenClientId) {
        if (postLogoutRedirectUri == null || postLogoutRedirectUri.isBlank() || clientId == null) {
            return null;
        }
        // a post-logout redirect is only honored for the client the ID token was issued to
        if (tokenClientId == null || !tokenClientId.equals(clientId)) {
            return null;
        }
        ClientRegistrationStore store = server.getIssuanceServer().getClientStore();
        Optional<RegisteredClient> registered = store.findByClientId(clientId);
        if (!registered.isPresent()) {
            return null;
        }
        return registered.get().getAllowedRedirectUris().contains(postLogoutRedirectUri)
                ? postLogoutRedirectUri
                : null;
    }
}
