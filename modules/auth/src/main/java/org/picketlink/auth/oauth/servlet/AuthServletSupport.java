package org.picketlink.auth.oauth.servlet;

import java.nio.file.Path;
import org.picketlink.auth.oauth.admin.ClientRegistrationService;
import org.picketlink.auth.oauth.client.store.ClientRegistrationStore;
import org.picketlink.auth.oauth.client.store.JsonFileClientRegistrationStore;
import org.picketlink.auth.oauth.client.store.PersistingClientRegistry;
import org.picketlink.common.config.PicketLinkSecurityConfigPaths;

/**
 * Bootstraps auth servlets from {@link jakarta.servlet.ServletContext} attributes.
 */
public final class AuthServletSupport {

    public static final String INIT_PARAM_CLIENTS_FILE = PicketLinkSecurityConfigPaths.AUTH_CLIENTS_FILE_PROPERTY;

    private AuthServletSupport() {
    }

    public static PersistingClientRegistry createDefaultRegistry(Path clientsFile) {
        ClientRegistrationStore store = new JsonFileClientRegistrationStore(clientsFile);
        return new PersistingClientRegistry(store);
    }

    public static ClientRegistrationService createRegistrationService(ClientRegistrationStore store) {
        return new ClientRegistrationService(store);
    }

    public static Class<VirtualResourcesServlet> virtualResourcesServletClass() {
        return VirtualResourcesServlet.class;
    }

    public static Class<ClientRegistrationServlet> clientRegistrationServletClass() {
        return ClientRegistrationServlet.class;
    }

    public static Class<OAuthTokenEndpointServlet> tokenEndpointServletClass() {
        return OAuthTokenEndpointServlet.class;
    }
}
