package org.picketlink.auth.oauth.store;

import org.picketlink.common.db.SqlDialect;
import org.picketlink.common.db.SqlDialects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Document store contract against SQLite (default embedded test database) plus a gated
 * PostgreSQL run — see {@link PostgresStoreIT}. H2 is banned in this repository.
 */
class JdbcClobDocumentStoreTest {

    @TempDir
    Path tempDir;

    private JdbcClobDocumentStore sqliteStore(String name) {
        // every store call opens a fresh connection, so persistence across "restarts" is
        // exercised implicitly by the file-backed database
        return new JdbcClobDocumentStore(new DriverManagerConnectionSource(
                "jdbc:sqlite:" + tempDir.resolve(name + ".db"), null, null));
    }

    @Test
    void sqliteShouldRoundTripDocumentAndIncrementVersion() {
        JdbcClobDocumentStore store = sqliteStore("roundtrip");
        assertNull(store.load("clients"));
        assertEquals(0L, store.currentVersion("clients"));

        long v1 = store.save("clients", "{\"version\":1,\"clients\":[]}", 0L);
        assertEquals(1L, v1);
        assertEquals("{\"version\":1,\"clients\":[]}", store.load("clients"));

        long v2 = store.save("clients", "{\"version\":2}", v1);
        assertEquals(2L, v2);
    }

    @Test
    void sqliteShouldRejectConcurrentUpdate() {
        JdbcClobDocumentStore store = sqliteStore("concurrent");
        store.save("clients", "{}", 0L);
        long version = store.currentVersion("clients");
        store.save("clients", "{\"other\":1}", version);
        assertThrows(DocumentConcurrentUpdateException.class,
                () -> store.save("clients", "{\"stale\":1}", version));
    }

    @Test
    void sqliteShouldSurviveRestartAndLargeDocuments() {
        JdbcClobDocumentStore store = sqliteStore("restart");
        store.save("clients", "{\"persisted\":true}", 0L);

        StringBuilder large = new StringBuilder("{\"data\":\"");
        for (int i = 0; i < 100_000; i++) {
            large.append('x');
        }
        large.append("\"}");
        store.save("clients", large.toString(), store.currentVersion("clients"));

        JdbcClobDocumentStore reopened = sqliteStore("restart");
        assertEquals(large.toString(), reopened.load("clients"));
    }

    @Test
    void dialectsShouldRenderEngineSpecificSql() {
        assertEquals("TEXT", SqlDialects.SQLITE.textType());
        assertEquals("TEXT", SqlDialects.POSTGRES.textType());
        assertEquals("CLOB", SqlDialects.ORACLE.textType());
        assertEquals("SELECT x LIMIT 10", SqlDialects.SQLITE.limitRows("SELECT x", 10));
        assertEquals("SELECT x LIMIT 10", SqlDialects.POSTGRES.limitRows("SELECT x", 10));
        assertEquals("SELECT x FETCH FIRST 10 ROWS ONLY", SqlDialects.ORACLE.limitRows("SELECT x", 10));
        assertEquals(SqlDialects.SQLITE, SqlDialects.forUrl("jdbc:sqlite:file.db"));
        assertEquals(SqlDialects.ORACLE, SqlDialects.forUrl("jdbc:oracle:thin:@db"));
        assertEquals(SqlDialects.POSTGRES, SqlDialects.forUrl("jdbc:postgresql://db/pl"));
        assertEquals(SqlDialects.POSTGRES, SqlDialects.forUrl(null));
    }
}
