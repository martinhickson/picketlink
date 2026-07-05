package org.picketlink.common.config;

import java.nio.file.Path;

/**
 * Zero-configuration default paths for PicketLink JSON security stores on WildFly.
 *
 * <p>Default directory (first match wins):
 * <ol>
 *   <li>{@code -Dpicketlink.config.security.dir=...}</li>
 *   <li>{@code -Dpicketlink.idm.document.file.dir=...} (legacy alias)</li>
 *   <li>{@code ${jboss.server.config.dir}/security}</li>
 *   <li>{@code ${jboss.home}/standalone/configuration/security}</li>
 *   <li>{@code ${user.dir}/security}</li>
 * </ol>
 *
 * <p>Default files in that directory:
 * <ul>
 *   <li>IDM realm document: {@value #DEFAULT_IDM_REALM_FILENAME}</li>
 *   <li>OAuth client registrations: {@value #DEFAULT_AUTH_CLIENTS_FILENAME}</li>
 * </ul>
 */
public final class PicketLinkSecurityConfigPaths {

    public static final String SECURITY_DIR_PROPERTY = "picketlink.config.security.dir";
    /** Legacy alias; prefer {@link #SECURITY_DIR_PROPERTY}. */
    public static final String IDM_FILE_DIR_PROPERTY = "picketlink.idm.document.file.dir";
    public static final String IDM_REALM_FILE_PROPERTY = "picketlink.idm.document.file";
    public static final String AUTH_CLIENTS_FILE_PROPERTY = "picketlink.auth.clients.file";
    public static final String REALM_CONFIG_FILE_PROPERTY = "picketlink.idm.realm.config.file";

    public static final String SECURITY_SUBDIR = "security";
    public static final String DEFAULT_IDM_REALM_FILENAME = "picketlink-db.json";
    public static final String DEFAULT_AUTH_CLIENTS_FILENAME = "picketlink-auth-clients.json";
    public static final String DEFAULT_REALM_CONFIG_FILENAME = "picketlink-realm-config.json";

    private PicketLinkSecurityConfigPaths() {
    }

    public static Path resolveSecurityConfigDirectory() {
        String configured = firstNonBlank(
                System.getProperty(SECURITY_DIR_PROPERTY),
                System.getProperty(IDM_FILE_DIR_PROPERTY));
        if (configured != null) {
            return Path.of(configured.trim());
        }
        String jbossConfig = System.getProperty("jboss.server.config.dir");
        if (jbossConfig != null && !jbossConfig.isBlank()) {
            return Path.of(jbossConfig.trim(), SECURITY_SUBDIR);
        }
        String jbossHome = System.getProperty("jboss.home");
        if (jbossHome != null && !jbossHome.isBlank()) {
            return Path.of(jbossHome.trim(), "standalone", "configuration", SECURITY_SUBDIR);
        }
        return Path.of(System.getProperty("user.dir", "."), SECURITY_SUBDIR);
    }

    public static Path defaultIdmRealmDocumentFile() {
        String explicit = System.getProperty(IDM_REALM_FILE_PROPERTY);
        if (explicit != null && !explicit.isBlank()) {
            return Path.of(explicit.trim());
        }
        return resolveSecurityConfigDirectory().resolve(DEFAULT_IDM_REALM_FILENAME);
    }

    public static Path defaultAuthClientsFile() {
        String explicit = System.getProperty(AUTH_CLIENTS_FILE_PROPERTY);
        if (explicit != null && !explicit.isBlank()) {
            return Path.of(explicit.trim());
        }
        return resolveSecurityConfigDirectory().resolve(DEFAULT_AUTH_CLIENTS_FILENAME);
    }

    public static Path defaultRealmConfigFile() {
        String explicit = System.getProperty(REALM_CONFIG_FILE_PROPERTY);
        if (explicit != null && !explicit.isBlank()) {
            return Path.of(explicit.trim());
        }
        return resolveSecurityConfigDirectory().resolve(DEFAULT_REALM_CONFIG_FILENAME);
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }
}
