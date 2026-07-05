package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.picketlink.common.config.PicketLinkSecurityConfigPaths;

class IdmDocumentStoresTest {

    @AfterEach
    void clearProperties() {
        System.clearProperty("jboss.server.config.dir");
        System.clearProperty("jboss.home");
        System.clearProperty(PicketLinkSecurityConfigPaths.IDM_REALM_FILE_PROPERTY);
        System.clearProperty(PicketLinkSecurityConfigPaths.SECURITY_DIR_PROPERTY);
        IdmDocumentStores.resetForTests();
    }

    @Test
    void defaultRealmFileUsesWildFlySecurityDirectory() {
        System.setProperty("jboss.server.config.dir", "/opt/wildfly/standalone/configuration");
        Path file = IdmDocumentStores.defaultIdmRealmDocumentFile();
        assertEquals(
                Path.of("/opt/wildfly/standalone/configuration/security/picketlink-db.json"),
                file);
    }

    @Test
    void defaultRealmFileFallsBackToWildFlyHome() {
        System.setProperty("jboss.home", "/opt/wildfly");
        Path file = IdmDocumentStores.defaultIdmRealmDocumentFile();
        assertEquals(
                Path.of("/opt/wildfly/standalone/configuration/security/picketlink-db.json"),
                file);
    }

    @Test
    void singleFileStoreUsesExplicitJsonPath(@org.junit.jupiter.api.io.TempDir Path tempDir) throws Exception {
        Path realmFile = tempDir.resolve("security").resolve("picketlink-db.json");
        JsonFileIdmDocumentStore store = new JsonFileIdmDocumentStore(realmFile);
        assertFalse(store.getStoragePath().equals(tempDir));
        IdmRealmService service = new IdmRealmService(store);
        service.createUser(IdmDocumentStores.DEFAULT_DOCUMENT_ID, 0L, "alice", "secret", java.util.List.of("role1"));
        assertEquals(tempDir.resolve("security/picketlink-db.json"), realmFile);
    }
}
