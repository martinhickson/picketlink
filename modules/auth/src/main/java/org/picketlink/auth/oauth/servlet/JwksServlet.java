package org.picketlink.auth.oauth.servlet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;

/**
 * Serves the issuer's public signing keys as JWKS for plain-servlet deployments (the JAX-RS
 * equivalent is {@code JwksResource}). Typical mapping: {@code /jwks.json}. Unauthenticated by
 * design — public keys only.
 */
public class JwksServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient ManagedIssuanceServer server;

    public JwksServlet() {
    }

    public JwksServlet(ManagedIssuanceServer server) {
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
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(OAuthConstants.APPLICATION_JSON);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(server.getIssuanceManager().getSigningService().publicJwksJson());
    }
}
