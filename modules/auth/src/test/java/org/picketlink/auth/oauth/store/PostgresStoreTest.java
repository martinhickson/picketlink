package org.picketlink.auth.oauth.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * PostgreSQL run of the store contract. Gated on the environment:
 * {@code PICKETLINK_TEST_POSTGRES_URL} (+ {@code ..._USER} / {@code ..._PASSWORD}) — self-skips
 * when not set. Oracle follows the same pattern once an environment exists (not OSS).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PostgresStoreTest {

    private static final String URL = System.getenv("PICKETLINK_TEST_POSTGRES_URL");
    private static final String USER = System.getenv("PICKETLINK_TEST_POSTGRES_USER");
    private static final String PASSWORD = System.getenv("PICKETLINK_TEST_POSTGRES_PASSWORD");

    private DriverManagerConnectionSource source;

    @BeforeAll
    void setUp() throws SQLException {
        assumeTrue(URL != null && !URL.isBlank(),
                "PICKETLINK_TEST_POSTGRES_URL not set — skipping PostgreSQL contract run");
        source = new DriverManagerConnectionSource(URL, USER, PASSWORD);
        try (Connection connection = source.openConnection(); Statement statement = connection.createStatement()) {
            statement.execute("DROP TABLE IF EXISTS " + JdbcClobDocumentStore.TABLE_NAME);
            statement.execute("DROP TABLE IF EXISTS " + JdbcAccessTokenRegistry.TABLE_NAME);
        }
    }

    private DriverManagerConnectionSource source() {
        assumeTrue(source != null, "PostgreSQL not configured");
        return source;
    }

    @Test
    void postgresShouldRoundTripDocumentsWithOptimisticLocking() {
        JdbcClobDocumentStore store = new JdbcClobDocumentStore(source());
        assertNull(store.load("clients"));
        long v1 = store.save("clients", "{\"version\":1}", 0L);
        assertEquals("{\"version\":1}", store.load("clients"));
        long v2 = store.save("clients", "{\"version\":2}", v1);
        assertEquals(2L, v2);
        assertThrows(DocumentConcurrentUpdateException.class,
                () -> store.save("clients", "{\"stale\":1}", v1));
    }

    @Test
    void postgresShouldRoundTripLargeDocuments() {
        JdbcClobDocumentStore store = new JdbcClobDocumentStore(source());
        store.save("clients", "{\"seed\":true}", store.currentVersion("clients"));
        StringBuilder large = new StringBuilder("{\"data\":\"");
        for (int i = 0; i < 100_000; i++) {
            large.append('x');
        }
        large.append("\"}");
        store.save("clients", large.toString(), store.currentVersion("clients"));
        assertEquals(large.toString(), store.load("clients"));
    }

    @Test
    void postgresTokenRegistryShouldStoreListAndRemove() {
        JdbcAccessTokenRegistry registry = new JdbcAccessTokenRegistry(source());
        java.time.Instant now = java.time.Instant.now();
        registry.store(new org.picketlink.auth.oauth.model.AccessTokenRecord(
                "pg-token-value", "pg-client", new java.util.LinkedHashSet<>(java.util.List.of("read")),
                now, now.plusSeconds(300)));
        assertEquals("pg-client",
                registry.findByTokenValue("pg-token-value").get().getClientId());
        assertEquals(1, registry.list(10).size());
        registry.remove("pg-token-value");
        org.junit.jupiter.api.Assertions.assertTrue(
                registry.findByTokenValue("pg-token-value").isEmpty(),
                "token should be removed");
    }
}
