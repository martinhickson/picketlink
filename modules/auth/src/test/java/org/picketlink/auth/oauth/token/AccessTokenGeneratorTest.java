package org.picketlink.auth.oauth.token;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import org.junit.jupiter.api.Test;

class AccessTokenGeneratorTest {

    @Test
    void generatesUniqueTokens() {
        AccessTokenGenerator generator = new AccessTokenGenerator();

        String first = generator.generate();
        String second = generator.generate();

        assertFalse(first.isEmpty());
        assertNotEquals(first, second);
    }
}
