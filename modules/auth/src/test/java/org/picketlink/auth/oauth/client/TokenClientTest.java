package org.picketlink.auth.oauth.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The m2m time-saver: token fetch, caching, refresh-ahead-of-expiry and 401-recovery —
 * verified against a local token endpoint (no external network).
 */
class TokenClientTest {

    private HttpServer server;
    private final AtomicInteger requests = new AtomicInteger();
    private volatile String responseBody =
            "{\"access_token\":\"token-1\",\"token_type\":\"Bearer\",\"expires_in\":60}";
    private volatile String lastAuthorizationHeader;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/oauth/token", exchange -> {
            requests.incrementAndGet();
            lastAuthorizationHeader = exchange.getRequestHeaders().getFirst("Authorization");
            byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private String endpoint() {
        return "http://localhost:" + server.getAddress().getPort() + "/oauth/token";
    }

    @Test
    void shouldFetchTokenWithBasicClientAuthentication() throws Exception {
        TokenClient client = TokenClient.forClientCredentials(endpoint(), "my-client", "my-secret");
        assertEquals("token-1", client.token());

        String expected = "Basic " + Base64.getEncoder()
                .encodeToString("my-client:my-secret".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, lastAuthorizationHeader);
    }

    @Test
    void shouldCacheUntilNearExpiryThenRefresh() throws Exception {
        // controllable clock: start at T, advance past the refresh-ahead window
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(10_000));
        TokenClient client = TokenClient.forClientCredentials(endpoint(), "c", "s")
                .withClock(clock);
        assertEquals("token-1", client.token());
        assertEquals(1, requests.get());

        // still cached well before expiry
        clock.advance(Duration.ofSeconds(10));
        assertEquals("token-1", client.token());
        assertEquals(1, requests.get(), "no extra request expected while cached");

        // 45s into a 60s token: within the 30s refresh-ahead window -> new fetch
        responseBody = "{\"access_token\":\"token-2\",\"token_type\":\"Bearer\",\"expires_in\":60}";
        clock.advance(Duration.ofSeconds(35));
        assertEquals("token-2", client.token());
        assertEquals(2, requests.get());
    }

    @Test
    void invalidateForcesRefetch() throws Exception {
        TokenClient client = TokenClient.forClientCredentials(endpoint(), "c", "s");
        assertEquals("token-1", client.token());
        responseBody = "{\"access_token\":\"token-2\",\"token_type\":\"Bearer\",\"expires_in\":60}";
        client.invalidate();
        assertEquals("token-2", client.token());
        assertEquals(2, requests.get());
    }

    @Test
    void shouldFailClearlyOnErrorResponses() throws Exception {
        server.removeContext("/oauth/token");
        server.createContext("/oauth/token", exchange -> {
            byte[] body = "{\"error\":\"invalid_client\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        TokenClient client = TokenClient.forClientCredentials(endpoint(), "c", "bad");
        IOException error = assertThrows(IOException.class, client::token);
        assertTrue(error.getMessage().contains("401"));
    }

    /** Controllable clock for deterministic expiry tests. */
    private static final class MutableClock extends Clock {

        private volatile Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
