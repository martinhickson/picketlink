package org.picketlink.idm.realm.config;

import org.picketlink.idm.realm.IdmRealmProviderConfig;

public final class IdmRealmConfigDocument {

    private final String provider;
    private final String scimBaseUrl;
    private final boolean useDefaultBaseUrl;
    private final String scimContextPath;
    private final String bearerToken;
    private final boolean syncToDocument;
    private final String usersPath;
    private final String groupsPath;
    private final String rolesPath;

    public IdmRealmConfigDocument(String provider, String scimBaseUrl, boolean useDefaultBaseUrl, String scimContextPath,
            String bearerToken, boolean syncToDocument, String usersPath, String groupsPath, String rolesPath) {
        this.provider = normalizeProvider(provider);
        this.scimBaseUrl = scimBaseUrl == null ? "" : scimBaseUrl.trim();
        this.useDefaultBaseUrl = useDefaultBaseUrl;
        this.scimContextPath = scimContextPath == null || scimContextPath.isBlank()
                ? IdmRealmProviderConfig.DEFAULT_SCIM_CONTEXT_PATH : scimContextPath.trim();
        this.bearerToken = bearerToken == null ? "" : bearerToken.trim();
        this.syncToDocument = syncToDocument;
        this.usersPath = usersPath == null || usersPath.isBlank()
                ? IdmRealmProviderConfig.DEFAULT_SCIM_USERS_PATH : usersPath.trim();
        this.groupsPath = groupsPath == null || groupsPath.isBlank()
                ? IdmRealmProviderConfig.DEFAULT_SCIM_GROUPS_PATH : groupsPath.trim();
        this.rolesPath = rolesPath == null || rolesPath.isBlank()
                ? IdmRealmProviderConfig.DEFAULT_SCIM_ROLES_PATH : rolesPath.trim();
    }

    public static IdmRealmConfigDocument defaults() {
        return new IdmRealmConfigDocument(
                IdmRealmProviderConfig.PROVIDER_DOCUMENT,
                "",
                true,
                IdmRealmProviderConfig.DEFAULT_SCIM_CONTEXT_PATH,
                "",
                true,
                IdmRealmProviderConfig.DEFAULT_SCIM_USERS_PATH,
                IdmRealmProviderConfig.DEFAULT_SCIM_GROUPS_PATH,
                IdmRealmProviderConfig.DEFAULT_SCIM_ROLES_PATH);
    }

    public String getProvider() {
        return provider;
    }

    public String getScimBaseUrl() {
        return scimBaseUrl;
    }

    public boolean isUseDefaultBaseUrl() {
        return useDefaultBaseUrl;
    }

    public String getScimContextPath() {
        return scimContextPath;
    }

    public String getBearerToken() {
        return bearerToken;
    }

    public boolean isSyncToDocument() {
        return syncToDocument;
    }

    public String getUsersPath() {
        return usersPath;
    }

    public String getGroupsPath() {
        return groupsPath;
    }

    public String getRolesPath() {
        return rolesPath;
    }

    private static String normalizeProvider(String provider) {
        if (provider == null || provider.isBlank()) {
            return IdmRealmProviderConfig.PROVIDER_DOCUMENT;
        }
        String normalized = provider.trim().toLowerCase();
        if (IdmRealmProviderConfig.PROVIDER_SCIM.equals(normalized)) {
            return IdmRealmProviderConfig.PROVIDER_SCIM;
        }
        return IdmRealmProviderConfig.PROVIDER_DOCUMENT;
    }
}
