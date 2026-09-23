package org.picketlink.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.junit.jupiter.api.Test;

class OidcAuthorizationServerConfigTest {

    @Test
    void registersACallerSuppliedClientAndUser() {
        OidcAuthorizationServerConfig config = OidcAuthorizationServerConfig.builder("https://issuer.example/")
                .client(OidcClientRegistration.builder("rda-client", "rda-secret")
                        .redirectUri("https://rp.example/callback")
                        .scope("openid")
                        .scope("api.read")
                        .grantType("authorization_code")
                        .grantType("refresh_token")
                        .build())
                .user(new OidcUserRegistration("ada", "s3cret", List.of("admin")))
                .keystore(new OidcKeystoreConfig(
                        Path.of("/tmp/signing.jks"), "store-pw", "key-pw", "signing", "JKS"))
                .build();

        assertEquals("https://issuer.example", config.getIssuer());
        assertEquals("store-pw", config.getKeystore().getStorePassword());
        assertEquals("key-pw", config.getKeystore().getKeyPassword());
        assertEquals("signing", config.getKeystore().getAlias());

        Client client = new ConfiguredOidcDataProvider(config.getClients()).doGetClient("rda-client");
        assertEquals("rda-secret", client.getClientSecret());
        assertEquals(List.of("https://rp.example/callback"), client.getRedirectUris());
        assertTrue(client.getRegisteredScopes().contains("api.read"));

        UserSubject subject = ConfiguredSubjectCreator.subjectFor("ada", config.getUsers());
        assertEquals("ada", subject.getLogin());
        assertEquals(List.of("admin"), subject.getRoles());
        assertThrows(org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException.class,
                () -> ConfiguredSubjectCreator.subjectFor("user1", config.getUsers()));
    }
}
