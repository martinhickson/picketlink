package org.picketlink.oidc;

import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.cxf.Bus;
import org.picketlink.oidc.keystore.DynamicOidcKeyStore;

public final class OidcKeystoreSupport {

    private OidcKeystoreSupport() {
    }

    /**
     * Loads the signing keystore and applies CXF {@code rs.security.keystore.*} properties on the {@link Bus}.
     * Optional {@code -javaagent:.../picketlink-oidc-*-keystore-agent.jar} enables hot reload without restart.
     */
    public static DynamicOidcKeyStore bootstrap(Bus bus, Path keystorePath) throws Exception {
        return bootstrap(bus, new OidcKeystoreConfig(
                keystorePath,
                OidcDemoConstants.KEYSTORE_PASSWORD,
                OidcDemoConstants.KEYSTORE_KEY_PASSWORD,
                OidcDemoConstants.KEYSTORE_ALIAS,
                OidcDemoConstants.KEYSTORE_TYPE));
    }

    public static DynamicOidcKeyStore bootstrap(Bus bus, OidcKeystoreConfig keystore) throws Exception {
        if (keystore == null || keystore.getPath() == null || !Files.isRegularFile(keystore.getPath())) {
            throw new IllegalArgumentException("Missing OIDC signing keystore: "
                    + (keystore == null ? null : keystore.getPath()));
        }
        DynamicOidcKeyStore store = DynamicOidcKeyStore.load(keystore);
        store.bindBus(bus);
        return store;
    }
}
