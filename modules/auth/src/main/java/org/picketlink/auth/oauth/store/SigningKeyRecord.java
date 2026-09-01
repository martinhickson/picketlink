package org.picketlink.auth.oauth.store;

/**
 * Metadata entry of a signing key. Private key material stays in the Java keystore; only the
 * reference (alias) and public identity live in the JSON document.
 */
public final class SigningKeyRecord {

    private final String keyId;
    private final String algorithm;
    private final String keystoreAlias;
    private final boolean active;
    private final long createdAtEpochSeconds;

    public SigningKeyRecord(String keyId, String algorithm, String keystoreAlias, boolean active,
            long createdAtEpochSeconds) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.keystoreAlias = keystoreAlias;
        this.active = active;
        this.createdAtEpochSeconds = createdAtEpochSeconds;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getKeystoreAlias() {
        return keystoreAlias;
    }

    public boolean isActive() {
        return active;
    }

    public long getCreatedAtEpochSeconds() {
        return createdAtEpochSeconds;
    }
}
