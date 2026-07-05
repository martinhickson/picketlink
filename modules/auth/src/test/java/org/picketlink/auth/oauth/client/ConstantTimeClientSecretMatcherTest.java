package org.picketlink.auth.oauth.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ConstantTimeClientSecretMatcherTest {

    private final ConstantTimeClientSecretMatcher matcher = new ConstantTimeClientSecretMatcher();

    @Test
    void matchesEqualSecrets() {
        assertTrue(matcher.matches("s3cr3t", "s3cr3t"));
    }

    @Test
    void rejectsDifferentSecrets() {
        assertFalse(matcher.matches("s3cr3t", "wrong"));
    }

    @Test
    void rejectsNullValues() {
        assertFalse(matcher.matches(null, "s3cr3t"));
        assertFalse(matcher.matches("s3cr3t", null));
    }
}
