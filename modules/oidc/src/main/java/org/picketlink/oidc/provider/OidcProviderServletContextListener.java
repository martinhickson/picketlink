package org.picketlink.oidc.provider;

import java.util.Map;
import java.util.Optional;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.service.JwtClientCredentialsTokenService;

/**
 * Servlet bootstrap for the production OIDC provider: builds the underlying
 * {@link ManagedIssuanceServer} (store selection via {@code picketlink.auth.store}) and the
 * {@link OidcProviderServer} on top, then publishes everything the endpoint servlets need.
 *
 * <p>Subject authentication is pluggable: the {@code subjectAuthenticator} init-param names a
 * {@link SubjectAuthenticator} class with a no-arg constructor (default: deny all logins).
 *
 * <p>Typical mapping (see the module README):
 * {@code /authorize} {@link AuthorizationEndpointServlet}, {@code /token}
 * {@link OidcTokenEndpointServlet}, {@code /userinfo} {@link UserInfoServlet},
 * {@code /logout} {@link LogoutEndpointServlet}, {@code /.well-known/openid-configuration}
 * {@code DiscoveryServlet}, {@code /jwks.json} {@code JwksServlet}.
 */
public class OidcProviderServletContextListener implements ServletContextListener {

    public static final String INIT_PARAM_SUBJECT_AUTHENTICATOR = "subjectAuthenticator";

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
            ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(issuer)
                    .connectionSource(ManagedIssuanceServer.connectionSourceFromProperties())
                    .build();
            OidcProviderServer server = OidcProviderServer.builder(issuer, issuanceServer)
                    .subjectAuthenticator(resolveAuthenticator(servletContext))
                    .build();
            servletContext.setAttribute(OidcProviderServer.class.getName(), server);
            servletContext.setAttribute(ManagedIssuanceServer.class.getName(), issuanceServer);
            servletContext.setAttribute(JwtClientCredentialsTokenService.class.getName(),
                    issuanceServer.getTokenService());
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to start OIDC provider", ex);
        }
    }

    private static SubjectAuthenticator resolveAuthenticator(ServletContext servletContext) {
        String className = servletContext.getInitParameter(INIT_PARAM_SUBJECT_AUTHENTICATOR);
        if (className == null || className.isBlank()) {
            return OidcProviderServer.DENY_ALL;
        }
        try {
            return (SubjectAuthenticator) Class.forName(className.trim())
                    .getDeclaredConstructor()
                    .newInstance();
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException(
                    "Unable to instantiate SubjectAuthenticator " + className, ex);
        }
    }

    /** Convenience for the common "fixed user set" configuration. */
    public static SubjectAuthenticator fixedUsers(Map<String, String> users) {
        return new SubjectAuthenticator.InMemorySubjectAuthenticator(users);
    }

    /** Null-safe accessor used by tests and embedders. */
    public static Optional<OidcProviderServer> provider(ServletContext servletContext) {
        Object configured = servletContext.getAttribute(OidcProviderServer.class.getName());
        return configured instanceof OidcProviderServer
                ? Optional.of((OidcProviderServer) configured)
                : Optional.empty();
    }
}
