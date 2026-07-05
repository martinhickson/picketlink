package org.picketlink.oidc;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.cxf.Bus;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.rs.security.oauth2.grants.code.AuthorizationCodeGrantHandler;
import org.apache.cxf.rs.security.oauth2.grants.refresh.RefreshTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJSONProvider;
import org.apache.cxf.rs.security.oauth2.services.AccessTokenService;
import org.apache.cxf.rs.security.jose.jaxrs.JsonWebKeysProvider;
import org.apache.cxf.rs.security.oidc.idp.IdTokenResponseFilter;
import org.apache.cxf.rs.security.oidc.idp.OidcConfigurationService;
import org.apache.cxf.rs.security.oidc.idp.UserInfoService;
import org.picketlink.oidc.admin.OidcKeyAdminResource;
import org.picketlink.oidc.keystore.DynamicOidcKeyStore;
import org.picketlink.oidc.keystore.OidcKeyStorePhaseInterceptor;
import org.picketlink.oidc.keystore.ReloadableJwksService;

public final class OidcAuthorizationServerBootstrap {

    private OidcAuthorizationServerBootstrap() {
    }

    public static DemoOidcDataProvider mount(Bus bus, String issuerBaseUrl, String rpRedirectUri) {
        return mount(bus, issuerBaseUrl, rpRedirectUri, Collections.emptyList());
    }

    public static DemoOidcDataProvider mount(Bus bus, String issuerBaseUrl, String rpRedirectUri,
            List<Object> additionalServiceBeans) {
        String issuer = trimTrailingSlash(issuerBaseUrl);
        DemoOidcDataProvider dataProvider = new DemoOidcDataProvider(rpRedirectUri);
        DemoIdTokenProvider idTokenProvider = new DemoIdTokenProvider(issuer);

        DemoOidcAuthorizationCodeService authorizeService = new DemoOidcAuthorizationCodeService();
        authorizeService.setDataProvider(dataProvider);
        authorizeService.setSubjectCreator(new DemoOidcSubjectCreator());
        authorizeService.setScopesRequiringNoConsent(OidcDemoConstants.DEFAULT_SCOPES);

        AccessTokenService tokenService = new AccessTokenService();
        tokenService.setDataProvider(dataProvider);
        AuthorizationCodeGrantHandler codeHandler = new AuthorizationCodeGrantHandler();
        codeHandler.setDataProvider(dataProvider);
        RefreshTokenGrantHandler refreshHandler = new RefreshTokenGrantHandler();
        refreshHandler.setDataProvider(dataProvider);
        tokenService.setGrantHandlers(Arrays.asList(codeHandler, refreshHandler));

        IdTokenResponseFilter idTokenFilter = new IdTokenResponseFilter();
        idTokenFilter.setIdTokenProvider(idTokenProvider);
        tokenService.setResponseFilter(idTokenFilter);

        UserInfoService userInfoService = new UserInfoService();
        userInfoService.setOauthDataProvider(dataProvider);

        ReloadableJwksService keysService = new ReloadableJwksService();

        OidcConfigurationService configService = new OidcConfigurationService();
        configService.setIssuer(issuer);
        configService.setStripPathFromIssuerUri(false);
        configService.setAuthorizationEndpointAddress(issuer + "/oidc/authorize");
        configService.setTokenEndpointAddress(issuer + "/oidc/token");
        configService.setUserInfoEndpointAddress(issuer + "/oidc/userinfo");
        configService.setJwkEndpointAddress(issuer + "/oidc/jwks");
        configService.setEndSessionEndpointAddress(issuer + "/idp/logout");

        List<Object> serviceBeans = new ArrayList<>(Arrays.asList(
                authorizeService,
                tokenService,
                userInfoService,
                keysService,
                configService));
        DynamicOidcKeyStore keyStore = DynamicOidcKeyStore.getGlobal();
        if (keyStore != null) {
            serviceBeans.add(new OidcKeyAdminResource(keyStore, keysService));
        }
        serviceBeans.addAll(additionalServiceBeans);

        createServer(bus, "/", serviceBeans);

        return dataProvider;
    }

    private static void createServer(Bus bus, String address, List<Object> serviceBeans) {
        List<AbstractPhaseInterceptor<Message>> interceptors = new ArrayList<>();
        interceptors.add(new OidcServletSecurityContextInterceptor());
        if (DynamicOidcKeyStore.getGlobal() != null) {
            interceptors.add(new OidcKeyStorePhaseInterceptor());
        }
        JAXRSServerFactoryBean factory = new JAXRSServerFactoryBean();
        factory.setBus(bus);
        factory.setAddress(address);
        factory.setServiceBeans(serviceBeans);
        factory.setProviders(Arrays.asList(new OAuthJSONProvider(), new JsonWebKeysProvider()));
        for (AbstractPhaseInterceptor<Message> interceptor : interceptors) {
            factory.getInInterceptors().add(interceptor);
        }
        factory.create();
    }

    private static String trimTrailingSlash(String url) {
        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }
}
