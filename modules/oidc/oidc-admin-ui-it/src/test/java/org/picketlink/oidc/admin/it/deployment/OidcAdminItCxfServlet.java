package org.picketlink.oidc.admin.it.deployment;

import jakarta.servlet.ServletConfig;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJSONProvider;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.picketlink.oidc.OidcKeystoreSupport;
import org.picketlink.oidc.admin.OidcKeyAdminResource;
import org.picketlink.oidc.keystore.DynamicOidcKeyStore;
import org.picketlink.oidc.keystore.ReloadableJwksService;

public class OidcAdminItCxfServlet extends CXFNonSpringServlet {

    @Override
    protected void loadBus(ServletConfig servletConfig) {
        super.loadBus(servletConfig);
        String keystorePath = System.getProperty("picketlink.test.keystore.path");
        if (keystorePath == null || keystorePath.isBlank()) {
            throw new IllegalStateException("picketlink.test.keystore.path is required");
        }
        try {
            OidcKeystoreSupport.bootstrap(getBus(), Path.of(keystorePath));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to bootstrap OIDC keystore", ex);
        }
        DynamicOidcKeyStore keyStore = DynamicOidcKeyStore.getGlobal();
        ReloadableJwksService jwksService = new ReloadableJwksService();
        JAXRSServerFactoryBean factory = new JAXRSServerFactoryBean();
        factory.setBus(getBus());
        factory.setAddress("/");
        factory.setServiceBeans(Collections.singletonList(new OidcKeyAdminResource(keyStore, jwksService)));
        factory.setProviders(Arrays.asList(new OAuthJSONProvider(), new JacksonJsonProvider()));
        factory.create();
    }
}
