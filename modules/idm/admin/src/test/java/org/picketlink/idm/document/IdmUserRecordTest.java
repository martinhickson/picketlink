package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.List;
import org.junit.jupiter.api.Test;

class IdmUserRecordTest {

    @Test
    void createNewGeneratesEnabledUserWithRoles() {
        IdmUserRecord user = IdmUserRecord.createNew("alice", "hash", List.of("role1"));
        assertEquals("alice", user.getLoginName());
        assertEquals("hash", user.getPasswordHash());
        assertTrue(user.isEnabled());
        assertFalse(user.getId().isBlank());
    }

    @Test
    void withMethodsReturnUpdatedCopies() {
        IdmUserRecord original = new IdmUserRecord("u1", "alice", "hash", List.of("role1"), true);
        IdmUserRecord disabled = original.withEnabled(false);
        IdmUserRecord rehashed = original.withPasswordHash("new-hash");
        IdmUserRecord rerolled = original.withRoles(List.of("role1", "role2"));

        assertTrue(original.isEnabled());
        assertFalse(disabled.isEnabled());
        assertEquals("new-hash", rehashed.getPasswordHash());
        assertEquals(2, rerolled.getRoles().size());
        assertEquals("u1", rerolled.getId());
    }
}
