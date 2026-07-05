package org.picketlink.idm.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class IdmJdbcConnectionSourcesTest {

    private final List<String> propertiesToClear = new ArrayList<>();

    @BeforeEach
    void captureProperties() {
        propertiesToClear.clear();
    }

    @AfterEach
    void restoreProperties() {
        for (String property : propertiesToClear) {
            System.clearProperty(property);
        }
    }

    @Test
    void defaultsToJcaConnectionMode() {
        assertEquals("jca", IdmJdbcConnectionSources.resolveConnectionMode());
    }

    @Test
    void usesClassicModeWhenConfiguredExplicitly() {
        setProperty(IdmDocumentStores.JDBC_CONNECTION_PROPERTY, "url");
        assertEquals("url", IdmJdbcConnectionSources.resolveConnectionMode());
    }

    @Test
    void usesClassicModeWhenJdbcUrlIsConfiguredWithoutConnectionProperty() {
        setProperty(IdmDocumentStores.JDBC_URL_PROPERTY, "jdbc:h2:mem:legacy");
        assertEquals("url", IdmJdbcConnectionSources.resolveConnectionMode());
    }

    @Test
    void resolvesClassicConnectionSourceFromJdbcUrl() {
        setProperty(IdmDocumentStores.JDBC_CONNECTION_PROPERTY, "url");
        setProperty(IdmDocumentStores.JDBC_URL_PROPERTY, "jdbc:h2:mem:classic-mode");
        setProperty(IdmDocumentStores.JDBC_DRIVER_PROPERTY, "org.h2.Driver");

        IdmJdbcConnectionSource source = IdmJdbcConnectionSources.fromSystemProperties();
        assertInstanceOf(DriverManagerJdbcConnectionSource.class, source);
    }

    private void setProperty(String name, String value) {
        propertiesToClear.add(name);
        System.setProperty(name, value);
    }
}
