package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.List;
import org.junit.jupiter.api.Test;

class IdmDocumentJsonCodecTest {

    @Test
    void roundTripsRealmDocument() {
        IdmRealmDocument original = new IdmRealmDocument(
                "picketlink-idm-realm",
                2L,
                List.of(new IdmUserRecord("u1", "alice", "$2a$hash", List.of("role1", "role2"), true)));
        String json = IdmDocumentJsonCodec.write(original);
        IdmRealmDocument restored = IdmDocumentJsonCodec.read("fallback-id", json);
        assertEquals(original.getDocumentId(), restored.getDocumentId());
        assertEquals(original.getVersion(), restored.getVersion());
        assertEquals(1, restored.getUsers().size());
        assertEquals("alice", restored.getUsers().get(0).getLoginName());
        assertEquals(2, restored.getUsers().get(0).getRoles().size());
        assertTrue(restored.getUsers().get(0).isEnabled());
    }

    @Test
    void readsEmptyDocumentWhenJsonMissing() {
        IdmRealmDocument empty = IdmDocumentJsonCodec.read("picketlink-idm-realm", null);
        assertEquals("picketlink-idm-realm", empty.getDocumentId());
        assertEquals(0L, empty.getVersion());
        assertTrue(empty.getUsers().isEmpty());
    }

    @Test
    void escapesSpecialCharactersInLoginName() {
        IdmRealmDocument document = new IdmRealmDocument(
                "doc",
                1L,
                List.of(new IdmUserRecord("u1", "user\nname", "hash", List.of("role1"), false)));
        String json = IdmDocumentJsonCodec.write(document);
        IdmRealmDocument restored = IdmDocumentJsonCodec.read("doc", json);
        assertEquals("user\nname", restored.getUsers().get(0).getLoginName());
        assertFalse(restored.getUsers().get(0).isEnabled());
    }
}
