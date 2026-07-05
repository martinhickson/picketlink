package org.picketlink.auth.oauth.client.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;

class ClientRegistrationJsonCodecTest {

    @Test
    void roundTripsClients() {
        RegisteredClient client = RegisteredClient.builder("service-a", "secret")
                .scope("api.read")
                .scope("api.write")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                .build();

        String json = ClientRegistrationJsonCodec.write(List.of(client));
        List<RegisteredClient> restored = ClientRegistrationJsonCodec.read(json);

        assertEquals(1, restored.size());
        assertEquals("service-a", restored.get(0).getClientId());
        assertEquals("secret", restored.get(0).getClientSecret());
        assertTrue(restored.get(0).getScopes().contains("api.read"));
        assertEquals(TokenEndpointAuthMethod.CLIENT_SECRET_POST,
                restored.get(0).getTokenEndpointAuthMethod());
        assertTrue(json.contains(OAuthConstants.TOKEN_ENDPOINT_AUTH_POST));
    }
}
