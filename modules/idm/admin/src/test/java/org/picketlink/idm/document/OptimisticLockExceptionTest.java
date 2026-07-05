package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class OptimisticLockExceptionTest {

    @Test
    void exposesExpectedAndActualVersions() {
        OptimisticLockException ex = new OptimisticLockException("picketlink-idm-realm", 1L, 3L);
        assertEquals(1L, ex.getExpectedVersion());
        assertEquals(3L, ex.getActualVersion());
        assertTrue(ex.getMessage().contains("picketlink-idm-realm"));
        assertTrue(ex.getMessage().contains("expected version 1"));
        assertTrue(ex.getMessage().contains("but was 3"));
    }
}
