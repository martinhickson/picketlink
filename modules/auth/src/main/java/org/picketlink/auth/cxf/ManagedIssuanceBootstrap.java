package org.picketlink.auth.cxf;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.cxf.Bus;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJSONProvider;
import org.picketlink.auth.oauth.admin.AdminScopeFilter;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.rest.JwksResource;

/**
 * Mounts the managed JWT issuance stack on Apache CXF/JAX-RS: the admin API plus the JWKS
 * endpoint, both guarded by {@link AdminScopeFilter} (bearer token with the {@code auth-admin}
 * scope). Complements {@link ClientCredentialsAuthServerBootstrap}, which mounts the token
 * endpoint itself.
 */
public final class ManagedIssuanceBootstrap {

    private ManagedIssuanceBootstrap() {
    }

    public static ManagedIssuanceServer mount(Bus bus, ManagedIssuanceServer server) {
        return mount(bus, "/", server);
    }

    public static ManagedIssuanceServer mount(Bus bus, String address, ManagedIssuanceServer server) {
        List<Object> serviceBeans = new ArrayList<>();
        serviceBeans.addAll(server.getAdminResources());
        serviceBeans.add(new JwksResource(server.getIssuanceManager()));

        JAXRSServerFactoryBean factory = new JAXRSServerFactoryBean();
        factory.setBus(bus);
        factory.setAddress(address);
        factory.setServiceBeans(serviceBeans);
        factory.setProviders(Arrays.asList(
                new OAuthJSONProvider(),
                new AdminScopeFilter(server.getIssuanceManager())));
        factory.create();
        return server;
    }
}
