package org.picketlink.idm.realm.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.picketlink.idm.realm.IdmRealmProviderConfig;

class JsonFileIdmRealmConfigStoreTest {

    @TempDir
    Path tempDir;

    @AfterEach
    void reset() {
        IdmRealmConfigStores.resetForTests();
    }

    @Test
    void persistsProviderSettings(@TempDir Path dir) throws Exception {
        Path configFile = dir.resolve("picketlink-realm-config.json");
        JsonFileIdmRealmConfigStore store = new JsonFileIdmRealmConfigStore(configFile);
        IdmRealmConfigDocument saved = store.save(new IdmRealmConfigDocument(
                IdmRealmProviderConfig.PROVIDER_SCIM,
                "http://127.0.0.1:9999/scim",
                false,
                "/scim",
                "token",
                false,
                "/Users",
                "/Groups",
                "/Roles"));
        IdmRealmConfigDocument loaded = store.load();
        assertEquals(saved.getProvider(), loaded.getProvider());
        assertEquals("http://127.0.0.1:9999/scim", loaded.getScimBaseUrl());
        assertTrue(Files.exists(configFile));
    }
}
