package org.picketlink.auth.oauth.servlet;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.service.JwtClientCredentialsTokenService;

/**
 * Servlet bootstrap for the managed JWT issuance stack: builds a {@link ManagedIssuanceServer}
 * (store selection via {@code picketlink.auth.store} — JDBC CLOB documents, or in-memory) and
 * publishes it plus its token service as servlet context attributes for
 * {@link OAuthTokenEndpointServlet} and {@link AdminApiServlet}.
 *
 * <p>Configuration: {@code picketlink.auth.issuer} (or {@code PICKETLINK_AUTH_ISSUER}); for
 * JDBC also {@code picketlink.auth.jdbc.url|user|password} and
 * {@code picketlink.auth.keystore.path|password}.
 */
public class ManagedAuthServerServletContextListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent event) {
        ServletContext servletContext = event.getServletContext();
        try {
            String issuer = servletContext.getInitParameter("issuer");
            if (issuer == null || issuer.isBlank()) {
                issuer = ManagedIssuanceServer.issuerFromEnvironment();
            }
            if (issuer == null) {
                throw new IllegalStateException(
                        "Issuer is required: set the 'issuer' init-param or picketlink.auth.issuer");
            }
            ManagedIssuanceServer server = ManagedIssuanceServer.builder(issuer)
                    .connectionSource(ManagedIssuanceServer.connectionSourceFromProperties())
                    .build();
            servletContext.setAttribute(ManagedIssuanceServer.class.getName(), server);
            servletContext.setAttribute(JwtClientCredentialsTokenService.class.getName(),
                    server.getTokenService());
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to start managed issuance server", ex);
        }
    }
}
