package org.picketlink.idm.realm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.picketlink.idm.document.IdmDocumentStores;
import org.picketlink.idm.document.IdmUserRecord;
import org.picketlink.idm.document.JsonFileIdmDocumentStore;
import org.picketlink.idm.document.OptimisticLockException;
import org.picketlink.idm.realm.IdmRealmProviderConfig;
import org.picketlink.idm.realm.IdmRealmSnapshot;

class DocumentIdmRealmBackendTest {

    @TempDir
    Path tempDir;

    private DocumentIdmRealmBackend backend;
    private String documentId;

    @BeforeEach
    void setUp() {
        backend = new DocumentIdmRealmBackend(new JsonFileIdmDocumentStore(tempDir));
        documentId = IdmDocumentStores.DEFAULT_DOCUMENT_ID;
    }

    @Test
    void createsUpdatesAndDeletesUsers() throws Exception {
        IdmRealmSnapshot created = backend.createUser(documentId, 0L, "alice", "secret", List.of("role1"));
        assertEquals(1L, created.getVersion());
        assertEquals(IdmRealmProviderConfig.PROVIDER_DOCUMENT, created.getProvider());
        assertEquals("alice", created.getUsers().get(0).getLoginName());

        String userId = created.getUsers().get(0).getId();
        IdmRealmSnapshot updated = backend.updateUser(
                documentId, 1L, userId, "new-secret", List.of("role1", "role2"), false);
        assertEquals(2L, updated.getVersion());
        IdmUserRecord updatedUser = updated.getUsers().get(0);
        assertFalse(updatedUser.isEnabled());
        assertEquals(2, updatedUser.getRoles().size());
        IdmUserRecord reloaded = backend.findUser(documentId, "alice").orElseThrow();
        assertTrue(backend.verifyPassword(reloaded, "new-secret".toCharArray()));

        IdmRealmSnapshot deleted = backend.deleteUser(documentId, 2L, userId);
        assertEquals(3L, deleted.getVersion());
        assertTrue(deleted.getUsers().isEmpty());
    }

    @Test
    void rejectsDuplicateLoginName() throws Exception {
        backend.createUser(documentId, 0L, "alice", "secret", List.of("role1"));
        assertThrows(IllegalArgumentException.class,
                () -> backend.createUser(documentId, 1L, "alice", "other", List.of("role1")));
    }

    @Test
    void throwsOptimisticLockConflict() throws Exception {
        backend.createUser(documentId, 0L, "alice", "secret", List.of("role1"));
        assertThrows(OptimisticLockException.class,
                () -> backend.createUser(documentId, 0L, "bob", "secret", List.of("role1")));
    }

    @Test
    void findsUserByLoginNameIgnoringCase() throws Exception {
        backend.createUser(documentId, 0L, "Alice", "secret", List.of("role1"));
        assertTrue(backend.findUser(documentId, "alice").isPresent());
        assertTrue(backend.findUser(documentId, "ALICE").isPresent());
    }
}
