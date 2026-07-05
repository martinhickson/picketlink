package org.picketlink.idm.document;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Resolves {@link IdmJdbcConnectionSource} from system properties.
 *
 * <p>Two JDBC connection modes are supported when {@code picketlink.idm.document.store=jdbc}:
 * <ul>
 *   <li>{@code jca} (default) — look up a container-managed {@link javax.sql.DataSource} via JNDI,
 *       typically {@code java:jboss/datasources/...} on WildFly. Configure
 *       {@code -Dpicketlink.idm.document.jdbc.jndi=...} or infer the name from
 *       {@code persistence.xml} {@code <jta-data-source>}.</li>
 *   <li>{@code url} — classic {@link java.sql.DriverManager} with an explicit JDBC URL
 *       ({@code -Dpicketlink.idm.document.jdbc.url=...}) or JDBC properties inferred from
 *       {@code persistence.xml}.</li>
 * </ul>
 */
public final class IdmJdbcConnectionSources {

    private IdmJdbcConnectionSources() {
    }

    public static IdmJdbcConnectionSource fromSystemProperties() {
        return switch (resolveConnectionMode()) {
            case "url", "classic" -> new DriverManagerJdbcConnectionSource(resolveClassicJdbcProperties());
            case "jca" -> JcaDataSourceConnectionSource.fromJndiName(resolveJndiName());
            default ->             throw new IllegalStateException(
                    "Unsupported " + IdmDocumentStores.JDBC_CONNECTION_PROPERTY + " value: " + resolveConnectionMode()
                            + " (expected jca or url)");
        };
    }

    static String resolveConnectionMode() {
        String configured = System.getProperty(IdmDocumentStores.JDBC_CONNECTION_PROPERTY);
        if (configured != null && !configured.isBlank()) {
            return configured.trim().toLowerCase();
        }
        String url = System.getProperty(IdmDocumentStores.JDBC_URL_PROPERTY);
        if (url != null && !url.isBlank()) {
            return "url";
        }
        return "jca";
    }

    private static String resolveJndiName() {
        String configured = System.getProperty(IdmDocumentStores.JDBC_JNDI_PROPERTY);
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        String persistence = System.getProperty(
                IdmDocumentStores.JDBC_PERSISTENCE_PROPERTY, "/META-INF/persistence.xml");
        try {
            return PersistenceXmlConnectionConfig.jndiNameFromPersistence(persistence);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to infer JCA data source from " + persistence, ex);
        }
    }

    private static HibernateJdbcUrlInference.JdbcConnectionProperties resolveClassicJdbcProperties() {
        String url = System.getProperty(IdmDocumentStores.JDBC_URL_PROPERTY);
        if (url != null && !url.isBlank()) {
            return new HibernateJdbcUrlInference.JdbcConnectionProperties(
                    url.trim(),
                    System.getProperty(IdmDocumentStores.JDBC_DRIVER_PROPERTY),
                    System.getProperty(IdmDocumentStores.JDBC_USER_PROPERTY, ""),
                    System.getProperty(IdmDocumentStores.JDBC_PASSWORD_PROPERTY, ""));
        }
        String persistence = System.getProperty(
                IdmDocumentStores.JDBC_PERSISTENCE_PROPERTY, "/META-INF/persistence.xml");
        try {
            if (persistence.startsWith("/") || persistence.startsWith("classpath:")) {
                String resource = persistence.startsWith("classpath:")
                        ? persistence.substring("classpath:".length())
                        : persistence;
                return HibernateJdbcUrlInference.fromClasspathResource(resource);
            }
            return HibernateJdbcUrlInference.fromPersistenceXml(Path.of(persistence));
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to infer JDBC URL settings from " + persistence, ex);
        }
    }
}
