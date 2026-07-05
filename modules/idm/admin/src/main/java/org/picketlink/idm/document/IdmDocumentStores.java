package org.picketlink.idm.document;

import java.nio.file.Path;
import org.picketlink.common.config.PicketLinkSecurityConfigPaths;

/**
 * Selects the active {@link IdmDocumentStore} implementation.
 * Default: {@link JsonFileIdmDocumentStore}. Alternative: {@link JdbcClobIdmDocumentStore}
 * ({@code -Dpicketlink.idm.document.store=jdbc}).
 */
public final class IdmDocumentStores {

    public static final String DEFAULT_DOCUMENT_ID = "picketlink-idm-realm";
    public static final String STORE_PROPERTY = "picketlink.idm.document.store";
    /** Legacy alias for {@link PicketLinkSecurityConfigPaths#SECURITY_DIR_PROPERTY}. */
    public static final String FILE_DIR_PROPERTY = PicketLinkSecurityConfigPaths.IDM_FILE_DIR_PROPERTY;
    public static final String FILE_PATH_PROPERTY = PicketLinkSecurityConfigPaths.IDM_REALM_FILE_PROPERTY;
    public static final String JDBC_CONNECTION_PROPERTY = "picketlink.idm.document.jdbc.connection";
    public static final String JDBC_JNDI_PROPERTY = "picketlink.idm.document.jdbc.jndi";
    public static final String JDBC_URL_PROPERTY = "picketlink.idm.document.jdbc.url";
    public static final String JDBC_USER_PROPERTY = "picketlink.idm.document.jdbc.user";
    public static final String JDBC_PASSWORD_PROPERTY = "picketlink.idm.document.jdbc.password";
    public static final String JDBC_DRIVER_PROPERTY = "picketlink.idm.document.jdbc.driver";
    public static final String JDBC_PERSISTENCE_PROPERTY = "picketlink.idm.document.jdbc.persistence";

    private static volatile IdmDocumentStore globalStore;

    private IdmDocumentStores() {
    }

    public static IdmDocumentStore globalStore() {
        IdmDocumentStore current = globalStore;
        if (current == null) {
            synchronized (IdmDocumentStores.class) {
                current = globalStore;
                if (current == null) {
                    current = createStore();
                    globalStore = current;
                }
            }
        }
        return current;
    }

    public static void resetForTests() {
        globalStore = null;
    }

    private static IdmDocumentStore createStore() {
        String type = System.getProperty(STORE_PROPERTY, "file").trim().toLowerCase();
        if ("jdbc".equals(type)) {
            return new JdbcClobIdmDocumentStore(IdmJdbcConnectionSources.fromSystemProperties());
        }
        return new JsonFileIdmDocumentStore(PicketLinkSecurityConfigPaths.defaultIdmRealmDocumentFile());
    }

    static Path defaultIdmRealmDocumentFile() {
        return PicketLinkSecurityConfigPaths.defaultIdmRealmDocumentFile();
    }
}
