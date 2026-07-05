package org.picketlink.auth.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;

class ClientCredentialsAuthServerTest {

    @Test
    void buildsConfiguredAuthorizationServer() {
        ClientCredentialsAuthServer authServer = ClientCredentialsAuthServer.builder(
                        "https://auth.example",
                        "https://auth.example/oauth/token")
                .accessTokenLifetimeSeconds(900L)
                .scopesSupported(java.util.List.of("api.read"))
                .build();

        authServer.getClientRegistry().register(RegisteredClient.builder("demo", "secret")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                .build());

        assertNotNull(authServer.getTokenService());
        assertEquals(900L, authServer.getTokenService().getAccessTokenLifetimeSeconds());
        assertEquals("https://auth.example", authServer.getMetadata().getIssuer());
    }
}
