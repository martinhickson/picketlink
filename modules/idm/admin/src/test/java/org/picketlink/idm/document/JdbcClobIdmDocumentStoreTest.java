package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JdbcClobIdmDocumentStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void persistsDocumentWithOptimisticLocking() throws Exception {
        String jdbcUrl = "jdbc:sqlite:" + tempDir.resolve("idm-doc-test.db");
        IdmJdbcConnectionSource connectionSource = new DriverManagerJdbcConnectionSource(
                new HibernateJdbcUrlInference.JdbcConnectionProperties(jdbcUrl, "org.sqlite.JDBC", null, null));
        JdbcClobIdmDocumentStore store = new JdbcClobIdmDocumentStore(connectionSource);
        IdmRealmService service = new IdmRealmService(store);

        IdmRealmDocument created = service.createUser("picketlink-idm-realm", 0L, "user1", "password1",
                java.util.List.of("role1"));
        assertEquals(1L, created.getVersion());

        IdmRealmDocument reloaded = store.load("picketlink-idm-realm");
        assertEquals(1L, reloaded.getVersion());
        assertEquals(1, reloaded.getUsers().size());

        assertThrows(OptimisticLockException.class,
                () -> service.createUser("picketlink-idm-realm", 0L, "user2", "password2", java.util.List.of("role1")));

        IdmRealmDocument updated = service.createUser("picketlink-idm-realm", 1L, "user2", "password2",
                java.util.List.of("role1"));
        assertEquals(2L, updated.getVersion());
        assertEquals(2, updated.getUsers().size());
        assertTrueTableExists(jdbcUrl);
    }

    @Test
    void persistsDocumentThroughJcaDataSource() throws Exception {
        String jdbcUrl = "jdbc:sqlite:" + tempDir.resolve("jca-idm-doc-test.db");
        javax.sql.DataSource dataSource = new SqliteTestDataSource(jdbcUrl);

        JcaDataSourceConnectionSource connectionSource =
                new JcaDataSourceConnectionSource("java:comp/env/jdbc/ExampleDS", dataSource);
        JdbcClobIdmDocumentStore store = new JdbcClobIdmDocumentStore(connectionSource);
        IdmRealmService service = new IdmRealmService(store);

        IdmRealmDocument created = service.createUser("picketlink-idm-realm", 0L, "user1", "password1",
                java.util.List.of("role1"));
        assertEquals(1L, created.getVersion());
        assertEquals("java:comp/env/jdbc/ExampleDS", connectionSource.jndiName());
    }

    @Test
    void infersJdbcUrlFromPersistenceXml(@TempDir Path dir) throws Exception {
        Path persistence = dir.resolve("persistence.xml");
        Files.writeString(persistence, """
                <persistence>
                  <persistence-unit name="test">
                    <properties>
                      <property name="jakarta.persistence.jdbc.driver" value="org.sqlite.JDBC"/>
                      <property name="jakarta.persistence.jdbc.url" value="jdbc:sqlite:inferred.db"/>
                      <property name="jakarta.persistence.jdbc.user" value=""/>
                      <property name="jakarta.persistence.jdbc.password" value=""/>
                    </properties>
                  </persistence-unit>
                </persistence>
                """);
        HibernateJdbcUrlInference.JdbcConnectionProperties props =
                HibernateJdbcUrlInference.fromPersistenceXml(persistence);
        assertEquals("jdbc:sqlite:inferred.db", props.url());
        assertEquals("org.sqlite.JDBC", props.driverClassName());
    }

    private static void assertTrueTableExists(String jdbcUrl) throws Exception {
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection(jdbcUrl);
                java.sql.PreparedStatement statement = connection.prepareStatement(
                        "SELECT COUNT(*) FROM picketlink_idm")) {
            try (java.sql.ResultSet rs = statement.executeQuery()) {
                rs.next();
                assertEquals(1, rs.getInt(1));
            }
        }
    }

    /** Minimal DataSource over the SQLite driver for the JCA connection-source test. */
    static final class SqliteTestDataSource implements javax.sql.DataSource {

        private final String url;

        SqliteTestDataSource(String url) {
            this.url = url;
        }

        @Override
        public java.sql.Connection getConnection() throws java.sql.SQLException {
            return java.sql.DriverManager.getConnection(url);
        }

        @Override
        public java.sql.Connection getConnection(String username, String password) throws java.sql.SQLException {
            return getConnection();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws java.sql.SQLException {
            throw new java.sql.SQLException("not a wrapper");
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }

        @Override
        public java.io.PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(java.io.PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public java.util.logging.Logger getParentLogger() {
            return java.util.logging.Logger.getGlobal();
        }
    }
}
