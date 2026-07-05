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
        Path dbFile = tempDir.resolve("idm-doc-test.mv.db");
        String jdbcUrl = "jdbc:h2:file:" + dbFile.toAbsolutePath().normalize().toString().replace('\\', '/');
        IdmJdbcConnectionSource connectionSource = new DriverManagerJdbcConnectionSource(
                new HibernateJdbcUrlInference.JdbcConnectionProperties(jdbcUrl, "org.h2.Driver", "sa", ""));
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
        org.h2.jdbcx.JdbcDataSource dataSource = new org.h2.jdbcx.JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:jca-idm-doc-test;DB_CLOSE_DELAY=-1");
        dataSource.setUser("sa");
        dataSource.setPassword("");

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
                      <property name="jakarta.persistence.jdbc.driver" value="org.h2.Driver"/>
                      <property name="jakarta.persistence.jdbc.url" value="jdbc:h2:mem:inferred"/>
                      <property name="jakarta.persistence.jdbc.user" value="sa"/>
                      <property name="jakarta.persistence.jdbc.password" value=""/>
                    </properties>
                  </persistence-unit>
                </persistence>
                """);
        HibernateJdbcUrlInference.JdbcConnectionProperties props =
                HibernateJdbcUrlInference.fromPersistenceXml(persistence);
        assertEquals("jdbc:h2:mem:inferred", props.url());
        assertEquals("org.h2.Driver", props.driverClassName());
    }

    private static void assertTrueTableExists(String jdbcUrl) throws Exception {
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection(jdbcUrl, "sa", "");
                java.sql.PreparedStatement statement = connection.prepareStatement(
                        "SELECT COUNT(*) FROM picketlink_idm")) {
            try (java.sql.ResultSet rs = statement.executeQuery()) {
                rs.next();
                assertEquals(1, rs.getInt(1));
            }
        }
    }
}
