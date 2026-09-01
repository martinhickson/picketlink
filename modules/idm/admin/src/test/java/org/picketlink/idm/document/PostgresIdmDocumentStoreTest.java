package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * PostgreSQL run of the IDM document store contract (the same strategy as the auth-module
 * store). Gated on {@code PICKETLINK_TEST_POSTGRES_URL} (+ {@code ..._USER} / {@code ..._PASSWORD})
 * — self-skips when not set.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PostgresIdmDocumentStoreTest {

    private static final String URL = System.getenv("PICKETLINK_TEST_POSTGRES_URL");
    private static final String USER = System.getenv("PICKETLINK_TEST_POSTGRES_USER");
    private static final String PASSWORD = System.getenv("PICKETLINK_TEST_POSTGRES_PASSWORD");

    private IdmJdbcConnectionSource source;

    @BeforeAll
    void setUp() throws Exception {
        assumeTrue(URL != null && !URL.isBlank(),
                "PICKETLINK_TEST_POSTGRES_URL not set — skipping PostgreSQL contract run");
        source = new DriverManagerJdbcConnectionSource(
                new HibernateJdbcUrlInference.JdbcConnectionProperties(URL, null, USER, PASSWORD));
        try (Connection connection = source.openConnection(); Statement statement = connection.createStatement()) {
            statement.execute("DROP TABLE IF EXISTS " + JdbcClobIdmDocumentStore.TABLE_NAME);
        }
    }

    private IdmJdbcConnectionSource source() {
        assumeTrue(source != null, "PostgreSQL not configured");
        return source;
    }

    @Test
    void roundTripsRealmDocumentWithOptimisticLocking() throws Exception {
        JdbcClobIdmDocumentStore store = new JdbcClobIdmDocumentStore(source());
        IdmRealmService service = new IdmRealmService(store);

        IdmRealmDocument created = service.createUser("pg-realm", 0L, "user1", "password1",
                java.util.List.of("role1"));
        assertEquals(1L, created.getVersion());

        IdmRealmDocument reloaded = store.load("pg-realm");
        assertEquals(1L, reloaded.getVersion());
        assertEquals(1, reloaded.getUsers().size());

        assertThrows(OptimisticLockException.class,
                () -> service.createUser("pg-realm", 0L, "user2", "password2", java.util.List.of("r")));
    }
}
