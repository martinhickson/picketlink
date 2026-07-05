package org.picketlink.auth.oauth.client.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;

class JsonFileClientRegistrationStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void persistsClientsToJsonFile() {
        Path file = tempDir.resolve("clients.json");
        JsonFileClientRegistrationStore store = new JsonFileClientRegistrationStore(file);
        RegisteredClient client = RegisteredClient.builder("demo", "secret")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build();

        store.save(client);

        assertTrue(Files.exists(file));
        assertTrue(store.findByClientId("demo").isPresent());
        assertEquals(1, store.findAll().size());

        JsonFileClientRegistrationStore reloaded = new JsonFileClientRegistrationStore(file);
        assertEquals("secret", reloaded.findByClientId("demo").get().getClientSecret());
        assertTrue(store.delete("demo"));
        assertFalse(store.findByClientId("demo").isPresent());
    }
}
