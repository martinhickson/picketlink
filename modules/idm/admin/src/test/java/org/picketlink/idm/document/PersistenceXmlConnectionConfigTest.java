package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PersistenceXmlConnectionConfigTest {

    @Test
    void readsJtaDataSourceJndiName() {
        String xml = """
                <persistence>
                  <persistence-unit name="test">
                    <jta-data-source>java:jboss/datasources/ExampleDS</jta-data-source>
                  </persistence-unit>
                </persistence>
                """;
        assertEquals("java:jboss/datasources/ExampleDS", PersistenceXmlConnectionConfig.jndiNameFromPersistenceContent(xml));
    }

    @Test
    void fallsBackToNonJtaDataSource(@TempDir Path dir) throws Exception {
        Path persistence = dir.resolve("persistence.xml");
        Files.writeString(persistence, """
                <persistence>
                  <persistence-unit name="test">
                    <non-jta-data-source>java:comp/env/jdbc/IdmDS</non-jta-data-source>
                  </persistence-unit>
                </persistence>
                """);
        assertEquals("java:comp/env/jdbc/IdmDS", PersistenceXmlConnectionConfig.jndiNameFromPersistence(persistence.toString()));
    }
}
