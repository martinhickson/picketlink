package org.picketlink.auth.cxf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.client.InMemoryClientRegistry;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry;

class ClientCredentialsOAuthDataProviderTest {

    private ClientCredentialsOAuthDataProvider dataProvider;

    @BeforeEach
    void setUp() {
        InMemoryClientRegistry clientRegistry = new InMemoryClientRegistry();
        clientRegistry.register(RegisteredClient.builder("service-a", "secret")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build());
        dataProvider = new ClientCredentialsOAuthDataProvider(clientRegistry, new InMemoryAccessTokenRegistry());
    }

    @Test
    void loadsRegisteredClient() throws Exception {
        Client client = dataProvider.getClient("service-a");

        assertNotNull(client);
        assertEquals("service-a", client.getClientId());
        assertEquals(OAuthConstants.CLIENT_CREDENTIALS_GRANT, client.getAllowedGrantTypes().get(0));
    }

    @Test
    void registersClientFromCxfModel() {
        Client client = new Client("service-b", "secret-b", true);
        client.setAllowedGrantTypes(java.util.Collections.singletonList(OAuthConstants.CLIENT_CREDENTIALS_GRANT));
        client.setRegisteredScopes(java.util.Collections.singletonList("api.write"));
        client.setTokenEndpointAuthMethod(OAuthConstants.TOKEN_ENDPOINT_AUTH_POST);

        dataProvider.setClient(client);

        assertEquals("service-b", dataProvider.getClient("service-b").getClientId());
    }
}
