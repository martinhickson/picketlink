package org.picketlink.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.grants.owner.ResourceOwnerGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.AccessTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.junit.jupiter.api.Test;

class ConfiguredResourceOwnerLoginHandlerTest {

    @Test
    void acceptsAConfiguredUserAndRejectsABadPassword() {
        OidcUserRegistration ada = new OidcUserRegistration("ada", "s3cret", List.of("admin"));
        ConfiguredResourceOwnerLoginHandler handler = new ConfiguredResourceOwnerLoginHandler(List.of(ada));

        UserSubject subject = handler.createSubject(null, "ada", "s3cret");
        assertEquals("ada", subject.getLogin());
        assertEquals(List.of("admin"), subject.getRoles());

        assertThrows(OAuthServiceException.class, () -> handler.createSubject(null, "ada", "wrong"));
        assertThrows(OAuthServiceException.class, () -> handler.createSubject(null, "unknown", "s3cret"));
    }

    @Test
    void mountsThePasswordGrantWhenAClientAndUserAllowIt() {
        OidcAuthorizationServerConfig config = server("rda-client", true, true);
        List<AccessTokenGrantHandler> handlers = OidcAuthorizationServerBootstrap.grantHandlers(
                new ConfiguredOidcDataProvider(config.getClients()), config);

        assertTrue(handlers.stream().anyMatch(handler ->
                handler instanceof ResourceOwnerGrantHandler
                        && handler.getSupportedGrantTypes().contains(OAuthConstants.RESOURCE_OWNER_GRANT)));
    }

    @Test
    void leavesThePasswordGrantOffWhenTheClientDoesNotAllowIt() {
        OidcAuthorizationServerConfig config = server("rda-client", false, true);
        List<AccessTokenGrantHandler> handlers = OidcAuthorizationServerBootstrap.grantHandlers(
                new ConfiguredOidcDataProvider(config.getClients()), config);

        assertTrue(handlers.stream().noneMatch(ResourceOwnerGrantHandler.class::isInstance));
    }

    @Test
    void leavesThePasswordGrantOffWhenNoUsersAreConfigured() {
        OidcAuthorizationServerConfig config = server("rda-client", true, false);
        List<AccessTokenGrantHandler> handlers = OidcAuthorizationServerBootstrap.grantHandlers(
                new ConfiguredOidcDataProvider(config.getClients()), config);

        assertTrue(handlers.stream().noneMatch(ResourceOwnerGrantHandler.class::isInstance));
    }

    private static OidcAuthorizationServerConfig server(String clientId, boolean password, boolean user) {
        OidcClientRegistration.Builder client = OidcClientRegistration.builder(clientId, "rda-secret")
                .redirectUri("https://rp.example/callback")
                .scope("openid")
                .grantType("authorization_code")
                .grantType("refresh_token");
        if (password) {
            client.grantType(OAuthConstants.RESOURCE_OWNER_GRANT);
        }
        OidcAuthorizationServerConfig.Builder builder = OidcAuthorizationServerConfig
                .builder("https://issuer.example")
                .client(client.build());
        if (user) {
            builder.user(new OidcUserRegistration("ada", "s3cret", List.of("admin")));
        }
        return builder.build();
    }
}
