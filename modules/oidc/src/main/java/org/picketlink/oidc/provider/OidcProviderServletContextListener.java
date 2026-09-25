package org.picketlink.oidc.provider;

import java.util.Map;
import java.util.Optional;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.service.JwtClientCredentialsTokenService;

/**
 * Servlet bootstrap for the production OIDC provider: builds the underlying
 * {@link ManagedIssuanceServer} (store selection via {@code picketlink.auth.store}) and the
 * {@link OidcProviderServer} on top, then publishes everything the endpoint servlets need.
 *
 * <p>Subject authentication is pluggable: the {@code subjectAuthenticator} init-param names a
 * {@link SubjectAuthenticator} class with a no-arg constructor (default: deny all logins).
 * {@link ConfiguredUsers} reads the {@code users} init-param instead. A confidential client
 * is seeded when {@code clientId} is set ({@code clientSecret}, {@code tokenEndpointAuthMethod},
 * {@code scopes}, {@code redirectUris}, {@code backchannelLogoutUrl}).
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
                    .basePath(servletContext.getInitParameter("basePath"))
                    .build();
            servletContext.setAttribute(OidcProviderServer.class.getName(), server);
            servletContext.setAttribute(ManagedIssuanceServer.class.getName(), issuanceServer);
            seedClient(servletContext, issuanceServer);
            servletContext.setAttribute(JwtClientCredentialsTokenService.class.getName(),
                    issuanceServer.getTokenService());
            mountStandardServlets(servletContext);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to start OIDC provider", ex);
        }
    }

    private static SubjectAuthenticator resolveAuthenticator(ServletContext servletContext) {
        String className = servletContext.getInitParameter(INIT_PARAM_SUBJECT_AUTHENTICATOR);
        if (className == null || className.isBlank()) {
            return OidcProviderServer.DENY_ALL;
        }
        if (ConfiguredUsers.class.getName().equals(className.trim())
                || SubjectAuthenticator.InMemorySubjectAuthenticator.class.getName().equals(className.trim())) {
            return new ConfiguredUsers(ConfiguredUsers.parse(
                    servletContext.getInitParameter(ConfiguredUsers.INIT_PARAM_USERS)));
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

    /**
     * Mounts the discovery set when {@code mountServlets} is not {@code false} and the
     * pattern is not already taken by {@code web.xml}.
     */
    private static void mountStandardServlets(ServletContext servletContext) {
        if ("false".equalsIgnoreCase(servletContext.getInitParameter("mountServlets"))) {
            return;
        }
        java.util.Set<String> taken = new java.util.HashSet<>();
        for (jakarta.servlet.ServletRegistration registration : servletContext.getServletRegistrations().values()) {
            taken.addAll(registration.getMappings());
        }
        mount(servletContext, taken, "oidc-authorize", AuthorizationEndpointServlet.class.getName(), "/authorize");
        mount(servletContext, taken, "oidc-par", PushedAuthorizationRequestServlet.class.getName(), "/par");
        mount(servletContext, taken, "oidc-device-authorization", DeviceAuthorizationServlet.class.getName(),
                "/device_authorization");
        mount(servletContext, taken, "oidc-device", DeviceVerificationServlet.class.getName(), "/device");
        mount(servletContext, taken, "oidc-token", OidcTokenEndpointServlet.class.getName(), "/token");
        mount(servletContext, taken, "oidc-userinfo", UserInfoServlet.class.getName(), "/userinfo");
        mount(servletContext, taken, "oidc-logout", LogoutEndpointServlet.class.getName(), "/logout");
        mount(servletContext, taken, "oidc-introspect", ProviderTokenManagementServlet.class.getName(), "/introspect");
        mount(servletContext, taken, "oidc-revoke", ProviderTokenManagementServlet.class.getName(), "/revoke");
        mount(servletContext, taken, "oidc-jwks", "org.picketlink.auth.oauth.servlet.JwksServlet", "/jwks.json");
        mount(servletContext, taken, "oidc-discovery", DiscoveryServlet.class.getName(),
                "/.well-known/openid-configuration");
    }

    private static void mount(ServletContext servletContext, java.util.Set<String> taken,
            String name, String className, String pattern) {
        if (taken.contains(pattern)) {
            return;
        }
        jakarta.servlet.ServletRegistration.Dynamic registration = servletContext.addServlet(name, className);
        if (registration != null) {
            registration.addMapping(pattern);
        }
    }

    private static void seedClient(ServletContext servletContext, ManagedIssuanceServer issuanceServer) {
        String clientId = servletContext.getInitParameter("clientId");
        if (clientId == null || clientId.isBlank()) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.builder(
                clientId.trim(), servletContext.getInitParameter("clientSecret"))
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.fromValue(
                        servletContext.getInitParameter("tokenEndpointAuthMethod")));
        for (String scope : split(servletContext.getInitParameter("scopes"))) {
            builder.scope(scope);
        }
        for (String redirectUri : split(servletContext.getInitParameter("redirectUris"))) {
            builder.redirectUri(redirectUri);
        }
        String logoutUrl = servletContext.getInitParameter("backchannelLogoutUrl");
        if (logoutUrl != null && !logoutUrl.isBlank()) {
            builder.backchannelLogoutUrl(logoutUrl.trim());
        }
        issuanceServer.getClientStore().save(builder.build());
    }

    private static String[] split(String raw) {
        if (raw == null || raw.isBlank()) {
            return new String[0];
        }
        return raw.trim().split("\\s+");
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
