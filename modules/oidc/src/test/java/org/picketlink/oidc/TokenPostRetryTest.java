package org.picketlink.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class TokenPostRetryTest {

    @Test
    void retriesOnceWhenTheConnectionCloses() throws IOException {
        AtomicInteger calls = new AtomicInteger();
        TokenPostRetry.once(() -> {
            if (calls.incrementAndGet() == 1) {
                throw new IOException("Connection closed");
            }
        });
        assertEquals(2, calls.get());
    }

    @Test
    void doesNotRetryOtherFailures() {
        AtomicInteger calls = new AtomicInteger();
        assertThrows(IOException.class, () -> TokenPostRetry.once(() -> {
            calls.incrementAndGet();
            throw new IOException("bad request");
        }));
        assertEquals(1, calls.get());
    }
}
