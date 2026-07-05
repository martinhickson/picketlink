package org.picketlink.idm.realm.config;

public final class IdmRealmConfigSnapshot {

    private final IdmRealmConfigDocument document;
    private final String configFile;
    private final String defaultScimBaseUrl;
    private final String effectiveScimBaseUrl;

    public IdmRealmConfigSnapshot(IdmRealmConfigDocument document, String configFile, String defaultScimBaseUrl,
            String effectiveScimBaseUrl) {
        this.document = document;
        this.configFile = configFile;
        this.defaultScimBaseUrl = defaultScimBaseUrl;
        this.effectiveScimBaseUrl = effectiveScimBaseUrl;
    }

    public IdmRealmConfigDocument getDocument() {
        return document;
    }

    public String getConfigFile() {
        return configFile;
    }

    public String getDefaultScimBaseUrl() {
        return defaultScimBaseUrl;
    }

    public String getEffectiveScimBaseUrl() {
        return effectiveScimBaseUrl;
    }
}
