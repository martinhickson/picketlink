package org.picketlink.idm.document;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads JCA/JNDI and JDBC settings from a JPA {@code persistence.xml}.
 */
public final class PersistenceXmlConnectionConfig {

    private static final Pattern JTA_DATA_SOURCE_PATTERN =
            Pattern.compile("<jta-data-source>\\s*([^<\\s]+)\\s*</jta-data-source>", Pattern.CASE_INSENSITIVE);
    private static final Pattern NON_JTA_DATA_SOURCE_PATTERN =
            Pattern.compile("<non-jta-data-source>\\s*([^<\\s]+)\\s*</non-jta-data-source>", Pattern.CASE_INSENSITIVE);

    private PersistenceXmlConnectionConfig() {
    }

    public static String jndiNameFromPersistence(String persistenceLocation) throws IOException {
        String xml = readPersistenceXml(persistenceLocation);
        return jndiNameFromPersistenceContent(xml);
    }

    public static String jndiNameFromPersistenceContent(String xml) {
        String jndiName = firstMatch(JTA_DATA_SOURCE_PATTERN, xml);
        if (jndiName == null) {
            jndiName = firstMatch(NON_JTA_DATA_SOURCE_PATTERN, xml);
        }
        if (jndiName == null || jndiName.isBlank()) {
            throw new IllegalStateException("No <jta-data-source> or <non-jta-data-source> found in persistence.xml");
        }
        return jndiName.trim();
    }

    private static String readPersistenceXml(String persistenceLocation) throws IOException {
        if (persistenceLocation.startsWith("classpath:")) {
            String resource = persistenceLocation.substring("classpath:".length());
            return readClasspathResource(resource);
        }
        Path persistenceXml = Path.of(persistenceLocation);
        if (Files.isRegularFile(persistenceXml)) {
            return Files.readString(persistenceXml, StandardCharsets.UTF_8);
        }
        if (persistenceLocation.startsWith("/")) {
            return readClasspathResource(persistenceLocation);
        }
        throw new IOException("persistence.xml not found: " + persistenceLocation);
    }

    private static String readClasspathResource(String resourcePath) throws IOException {
        try (InputStream input = PersistenceXmlConnectionConfig.class.getResourceAsStream(resourcePath)) {
            if (input == null) {
                throw new IOException("Missing persistence resource: " + resourcePath);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String firstMatch(Pattern pattern, String xml) {
        Matcher matcher = pattern.matcher(xml);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
}
