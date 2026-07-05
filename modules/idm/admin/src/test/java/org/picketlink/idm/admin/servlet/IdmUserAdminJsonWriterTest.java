package org.picketlink.idm.admin.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.picketlink.idm.document.IdmUserRecord;
import org.picketlink.idm.realm.IdmRealmProviderConfig;
import org.picketlink.idm.realm.IdmRealmSnapshot;

class IdmUserAdminJsonWriterTest {

    @Test
    void writesDocumentRealmSnapshot() {
        IdmRealmSnapshot snapshot = new IdmRealmSnapshot(
                "picketlink-idm-realm",
                2L,
                IdmRealmProviderConfig.PROVIDER_DOCUMENT,
                null,
                List.of(new IdmUserRecord("u1", "alice", "hash", List.of("role1"), true)),
                List.of("role1"),
                List.of());
        String json = IdmUserAdminJsonWriter.writeRealm(snapshot);
        assertTrue(json.contains("\"documentId\":\"picketlink-idm-realm\""));
        assertTrue(json.contains("\"provider\":\"document\""));
        assertTrue(json.contains("\"loginName\":\"alice\""));
        assertFalse(json.contains("scimBaseUrl"));
    }

    @Test
    void writesScimRealmSnapshot() {
        IdmRealmSnapshot snapshot = new IdmRealmSnapshot(
                "picketlink-idm-realm",
                0L,
                IdmRealmProviderConfig.PROVIDER_SCIM,
                "http://127.0.0.1:8080/scim",
                List.of(),
                List.of("administrator"),
                List.of("developers"));
        String json = IdmUserAdminJsonWriter.writeRealm(snapshot);
        assertTrue(json.contains("\"provider\":\"scim\""));
        assertTrue(json.contains("\"scimBaseUrl\":\"http://127.0.0.1:8080/scim\""));
        assertTrue(json.contains("\"roles\":[\"administrator\"]"));
        assertTrue(json.contains("\"groups\":[\"developers\"]"));
    }

    @Test
    void writesErrorAndConflictResponses() {
        assertEquals("{\"error\":\"bad request\"}", IdmUserAdminJsonWriter.writeError("bad request"));
        assertEquals("{\"error\":\"Optimistic lock conflict\",\"actualVersion\":3}",
                IdmUserAdminJsonWriter.writeConflict(3L));
        assertTrue(IdmUserAdminJsonWriter.writeError("quote \" and \\ slash").contains("\\\""));
    }
}
