package org.picketlink.oidc.provider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

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
        response.setHeader("Location", redirect);
        response.setStatus(HttpServletResponse.SC_FOUND);
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
