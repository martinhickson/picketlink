package org.picketlink.idm.document;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads JDBC connection properties from a JPA {@code persistence.xml} (Hibernate/EclipseLink),
 * for use by {@link JdbcClobIdmDocumentStore} when no explicit JDBC URL is configured.
 */
public final class HibernateJdbcUrlInference {

    private static final Pattern PROPERTY_PATTERN =
            Pattern.compile("<property\\s+name=\"([^\"]+)\"\\s+value=\"([^\"]*)\"\\s*/>");

    private HibernateJdbcUrlInference() {
    }

    public static JdbcConnectionProperties fromPersistenceXml(Path persistenceXml) throws IOException {
        if (!Files.isRegularFile(persistenceXml)) {
            throw new IOException("persistence.xml not found: " + persistenceXml);
        }
        String xml = Files.readString(persistenceXml, StandardCharsets.UTF_8);
        return fromPersistenceXmlContent(xml);
    }

    public static JdbcConnectionProperties fromClasspathResource(String resourcePath) throws IOException {
        try (InputStream input = HibernateJdbcUrlInference.class.getResourceAsStream(resourcePath)) {
            if (input == null) {
                throw new IOException("Missing persistence resource: " + resourcePath);
            }
            return fromPersistenceXmlContent(new String(input.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    public static JdbcConnectionProperties fromPersistenceXmlContent(String xml) {
        Properties properties = new Properties();
        Matcher matcher = PROPERTY_PATTERN.matcher(xml);
        while (matcher.find()) {
            properties.setProperty(matcher.group(1), matcher.group(2));
        }
        String url = firstNonBlank(
                properties.getProperty("jakarta.persistence.jdbc.url"),
                properties.getProperty("javax.persistence.jdbc.url"),
                properties.getProperty("hibernate.connection.url"));
        String driver = firstNonBlank(
                properties.getProperty("jakarta.persistence.jdbc.driver"),
                properties.getProperty("javax.persistence.jdbc.driver"),
                properties.getProperty("hibernate.connection.driver_class"));
        String user = firstNonBlank(
                properties.getProperty("jakarta.persistence.jdbc.user"),
                properties.getProperty("javax.persistence.jdbc.user"),
                properties.getProperty("hibernate.connection.username"),
                "");
        String password = firstNonBlank(
                properties.getProperty("jakarta.persistence.jdbc.password"),
                properties.getProperty("javax.persistence.jdbc.password"),
                properties.getProperty("hibernate.connection.password"),
                "");
        if (url == null || url.isBlank()) {
            throw new IllegalStateException("No JDBC URL found in persistence.xml");
        }
        return new JdbcConnectionProperties(url, driver, user, password);
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    public record JdbcConnectionProperties(String url, String driverClassName, String user, String password) {
    }
}
