package org.picketlink.oidc.keystore.bridge;

import java.security.KeyStore;
import java.util.Properties;

/**
 * JDK-only holder shared by the Byte Buddy agent and the deployment.
 * WildFly loads this package from the system class loader when
 * {@code jboss.modules.system.pkgs} includes it, so both sides see one instance.
 */
public final class OidcKeyStoreBridge {

    public static final String KEYSTORE_FILE = "rs.security.keystore.file";

    private static String managedPath;
    private static KeyStore keyStore;

    private OidcKeyStoreBridge() {
    }

    public static synchronized void publish(String path, KeyStore store) {
        keyStore = store;
        managedPath = path;
    }

    public static synchronized KeyStore current() {
        return keyStore;
    }

    /**
     * Arguments stay {@link Object} so the agent can load this class before CXF is on the classpath.
     */
    public static synchronized KeyStore enter(Object message, Object props) {
        if (keyStore == null || managedPath == null || !(props instanceof Properties properties)) {
            return null;
        }
        String file = properties.getProperty(KEYSTORE_FILE);
        if (!managedPath.equals(file)) {
            return null;
        }
        if (message != null) {
            clearExchangeCache(message, file);
        }
        return keyStore;
    }

    private static void clearExchangeCache(Object message, String file) {
        try {
            Object exchange = message.getClass().getMethod("getExchange").invoke(message);
            if (exchange != null) {
                exchange.getClass().getMethod("remove", Object.class).invoke(exchange, file);
            }
        } catch (ReflectiveOperationException ignored) {
            // The exchange cache is an optimization. The caller still receives the live store.
        }
    }
}
