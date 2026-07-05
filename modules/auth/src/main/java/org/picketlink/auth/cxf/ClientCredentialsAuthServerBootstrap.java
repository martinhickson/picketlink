package org.picketlink.auth.cxf;

import java.util.Arrays;
import java.util.Collections;
import org.apache.cxf.Bus;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.rs.security.oauth2.grants.clientcred.ClientCredentialsGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJSONProvider;
import org.apache.cxf.rs.security.oauth2.services.AccessTokenService;
import org.picketlink.auth.oauth.ClientCredentialsAuthServer;
import org.picketlink.auth.oauth.metadata.OAuthAuthorizationServerMetadataResource;
import org.picketlink.auth.oauth.servlet.OAuthTokenEndpointServlet;

/**
 * Mounts an OAuth 2.1 client-credentials authorization server on Apache CXF/JAX-RS.
 */
public final class ClientCredentialsAuthServerBootstrap {

    private ClientCredentialsAuthServerBootstrap() {
    }

    public static ClientCredentialsAuthServer mount(Bus bus, ClientCredentialsAuthServer authServer) {
        return mount(bus, "/", authServer);
    }

    public static ClientCredentialsAuthServer mount(Bus bus, String address,
            ClientCredentialsAuthServer authServer) {
        ClientCredentialsOAuthDataProvider dataProvider = new ClientCredentialsOAuthDataProvider(
                authServer.getClientRegistry(),
                authServer.getAccessTokenRegistry());
        dataProvider.setAccessTokenLifetime(authServer.getTokenService().getAccessTokenLifetimeSeconds());

        AccessTokenService tokenService = new AccessTokenService();
        tokenService.setDataProvider(dataProvider);
        ClientCredentialsGrantHandler grantHandler = new ClientCredentialsGrantHandler();
        grantHandler.setDataProvider(dataProvider);
        tokenService.setGrantHandler(grantHandler);

        OAuthAuthorizationServerMetadataResource metadataResource =
                new OAuthAuthorizationServerMetadataResource(authServer.getMetadata());

        JAXRSServerFactoryBean factory = new JAXRSServerFactoryBean();
        factory.setBus(bus);
        factory.setAddress(address);
        factory.setServiceBeans(Arrays.asList(tokenService, metadataResource));
        factory.setProviders(Collections.singletonList(new OAuthJSONProvider()));
        factory.create();

        return authServer;
    }

    /**
     * Returns the servlet class for container deployments that prefer a plain {@link jakarta.servlet}
     * endpoint (Tomcat, WildFly) without CXF.
     */
    public static Class<OAuthTokenEndpointServlet> servletClass() {
        return OAuthTokenEndpointServlet.class;
    }
}
