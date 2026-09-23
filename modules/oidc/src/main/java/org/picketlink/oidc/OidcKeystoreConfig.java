package org.picketlink.oidc;

import java.nio.file.Path;

/** Signing keystore the authorization server loads: path, passwords, alias, and type. */
public final class OidcKeystoreConfig {

    private final Path path;
    private final String storePassword;
    private final String keyPassword;
    private final String alias;
    private final String type;

    public OidcKeystoreConfig(Path path, String storePassword, String keyPassword, String alias, String type) {
        if (path == null) {
            throw new IllegalArgumentException("keystore path is required");
        }
        if (storePassword == null || keyPassword == null || alias == null || alias.isBlank()) {
            throw new IllegalArgumentException("keystore password, key password, and alias are required");
        }
        this.path = path;
        this.storePassword = storePassword;
        this.keyPassword = keyPassword;
        this.alias = alias;
        this.type = type == null || type.isBlank() ? OidcDemoConstants.KEYSTORE_TYPE : type;
    }

    public Path getPath() {
        return path;
    }

    public String getStorePassword() {
        return storePassword;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public String getAlias() {
        return alias;
    }

    public String getType() {
        return type;
    }
}
