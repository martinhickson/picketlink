package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.picketlink.idm.realm.IdmRealmProviderConfig;

class IdmRealmServiceTest {

    @TempDir
    Path tempDir;

    private IdmRealmService service;
    private String documentId;

    @BeforeEach
    void setUp() {
        service = new IdmRealmService(new JsonFileIdmDocumentStore(tempDir));
        documentId = IdmDocumentStores.DEFAULT_DOCUMENT_ID;
    }

    @Test
    void exposesSnapshotAndDocumentViews() throws Exception {
        IdmRealmDocument created = service.createUser(documentId, 0L, "alice", "secret", java.util.List.of("role1"));
        assertEquals(1L, created.getVersion());

        var snapshot = service.loadRealmSnapshot(documentId);
        assertEquals(IdmRealmProviderConfig.PROVIDER_DOCUMENT, snapshot.getProvider());
        assertEquals(1, snapshot.getUsers().size());
        assertEquals(1, service.listUsers(documentId).size());
        assertTrue(service.findUser(documentId, "alice").isPresent());
    }

    @Test
    void hashesPasswordConsistently() {
        String first = IdmRealmService.hashPassword("secret");
        String second = IdmRealmService.hashPassword("secret");
        assertTrue(first.startsWith("$2a$"));
        assertTrue(!first.equals(second));
    }
}
