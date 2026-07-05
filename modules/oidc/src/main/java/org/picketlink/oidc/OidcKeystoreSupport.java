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
        if (keystorePath == null || !Files.isRegularFile(keystorePath)) {
            throw new IllegalArgumentException("Missing OIDC signing keystore: " + keystorePath);
        }
        DynamicOidcKeyStore store = DynamicOidcKeyStore.load(
                keystorePath,
                OidcDemoConstants.KEYSTORE_PASSWORD,
                OidcDemoConstants.KEYSTORE_ALIAS);
        store.bindBus(bus);
        return store;
    }
}
