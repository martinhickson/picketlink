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
 * Oracle run of the store contract. Oracle is not OSS, so this self-skips unless the
 * environment provides {@code PICKETLINK_TEST_ORACLE_URL} (+ {@code ..._USER} / {@code ..._PASSWORD},
 * e.g. {@code jdbc:oracle:thin:@//host:1521/service}). The SQL itself is exercised through
 * {@link SqlDialects#ORACLE}; additionally verified against the dialect rendering in
 * {@link JdbcClobDocumentStoreTest#dialectsShouldRenderEngineSpecificSql()}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OracleStoreTest {

    private static final String URL = System.getenv("PICKETLINK_TEST_ORACLE_URL");
    private static final String USER = System.getenv("PICKETLINK_TEST_ORACLE_USER");
    private static final String PASSWORD = System.getenv("PICKETLINK_TEST_ORACLE_PASSWORD");

    private DriverManagerConnectionSource source;

    @BeforeAll
    void setUp() throws SQLException {
        assumeTrue(URL != null && !URL.isBlank(),
                "PICKETLINK_TEST_ORACLE_URL not set — skipping Oracle contract run");
        source = new DriverManagerConnectionSource(URL, USER, PASSWORD);
        try (Connection connection = source.openConnection(); Statement statement = connection.createStatement()) {
            statement.execute("DROP TABLE " + JdbcClobDocumentStore.TABLE_NAME);
            statement.execute("DROP TABLE " + JdbcAccessTokenRegistry.TABLE_NAME);
        }
    }

    private DriverManagerConnectionSource source() {
        assumeTrue(source != null, "Oracle not configured");
        return source;
    }

    @Test
    void oracleShouldRoundTripDocumentsWithOptimisticLocking() {
        JdbcClobDocumentStore store = new JdbcClobDocumentStore(source(), SqlDialects.ORACLE);
        assertNull(store.load("clients"));
        long v1 = store.save("clients", "{\"version\":1}", 0L);
        assertEquals("{\"version\":1}", store.load("clients"));
        long v2 = store.save("clients", "{\"version\":2}", v1);
        assertEquals(2L, v2);
        assertThrows(DocumentConcurrentUpdateException.class,
                () -> store.save("clients", "{\"stale\":1}", v1));
    }

    @Test
    void oracleShouldRoundTripLargeClobDocuments() {
        JdbcClobDocumentStore store = new JdbcClobDocumentStore(source(), SqlDialects.ORACLE);
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
    void oracleTokenRegistryShouldStoreListAndRemove() {
        JdbcAccessTokenRegistry registry = new JdbcAccessTokenRegistry(source(), SqlDialects.ORACLE);
        java.time.Instant now = java.time.Instant.now();
        registry.store(new org.picketlink.auth.oauth.model.AccessTokenRecord(
                "oracle-token-value", "oracle-client",
                new java.util.LinkedHashSet<>(java.util.List.of("read")),
                now, now.plusSeconds(300)));
        assertEquals("oracle-client",
                registry.findByTokenValue("oracle-token-value").get().getClientId());
        assertEquals(1, registry.list(10).size());
        registry.remove("oracle-token-value");
        org.junit.jupiter.api.Assertions.assertTrue(
                registry.findByTokenValue("oracle-token-value").isEmpty(),
                "token should be removed");
    }
}
