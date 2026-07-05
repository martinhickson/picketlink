package org.picketlink.auth.oauth.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;

class InMemoryClientRegistryTest {

    private InMemoryClientRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new InMemoryClientRegistry();
    }

    @Test
    void registersAndFindsClient() {
        RegisteredClient client = RegisteredClient.builder("demo", "secret")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build();
        registry.register(client);

        assertTrue(registry.findByClientId("demo").isPresent());
        assertEquals("secret", registry.findByClientId("demo").get().getClientSecret());
    }
}
