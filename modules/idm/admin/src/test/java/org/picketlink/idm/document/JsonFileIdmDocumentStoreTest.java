package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JsonFileIdmDocumentStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void savesWithOptimisticLocking() throws Exception {
        JsonFileIdmDocumentStore store = new JsonFileIdmDocumentStore(tempDir);
        IdmRealmService service = new IdmRealmService(store);
        IdmRealmDocument created = service.createUser("picketlink-idm-realm", 0L, "alice", "secret", java.util.List.of("role1"));
        assertEquals(1L, created.getVersion());
        assertEquals(1, created.getUsers().size());

        OptimisticLockException conflict = assertThrows(OptimisticLockException.class,
                () -> service.createUser("picketlink-idm-realm", 0L, "bob", "secret", java.util.List.of("role1")));
        assertEquals(1L, conflict.getActualVersion());

        IdmRealmDocument updated = service.createUser("picketlink-idm-realm", 1L, "bob", "secret", java.util.List.of("role1"));
        assertEquals(2L, updated.getVersion());
        assertEquals(2, updated.getUsers().size());
    }

    @Test
    void verifiesPasswordHash() throws Exception {
        JsonFileIdmDocumentStore store = new JsonFileIdmDocumentStore(tempDir);
        IdmRealmService service = new IdmRealmService(store);
        service.createUser("picketlink-idm-realm", 0L, "user1", "password1", java.util.List.of("role1"));
        IdmUserRecord user = service.findUser("picketlink-idm-realm", "user1").orElseThrow();
        assertTrue(service.verifyPassword(user, "password1".toCharArray()));
    }
}
