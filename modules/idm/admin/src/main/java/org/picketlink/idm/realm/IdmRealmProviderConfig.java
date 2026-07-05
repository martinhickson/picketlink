package org.picketlink.idm.realm;

import org.picketlink.idm.realm.config.IdmRealmConfigDocument;
import org.picketlink.idm.realm.config.IdmRealmConfigService;

/**
 * Effective realm provider configuration. JVM system properties override values persisted in
 * {@code picketlink-realm-config.json} (managed via the IDM admin UI).
 */
public final class IdmRealmProviderConfig {

    public static final String PROVIDER_PROPERTY = "picketlink.idm.realm.provider";
    public static final String SCIM_BASE_URL_PROPERTY = "picketlink.idm.realm.scim.baseUrl";
    public static final String SCIM_USE_DEFAULT_BASE_URL_PROPERTY = "picketlink.idm.realm.scim.useDefaultBaseUrl";
    public static final String SCIM_CONTEXT_PATH_PROPERTY = "picketlink.idm.realm.scim.contextPath";
    public static final String SCIM_BEARER_TOKEN_PROPERTY = "picketlink.idm.realm.scim.bearerToken";
    public static final String SCIM_SYNC_TO_DOCUMENT_PROPERTY = "picketlink.idm.realm.scim.syncToDocument";
    public static final String SCIM_USERS_PATH_PROPERTY = "picketlink.idm.realm.scim.usersPath";
    public static final String SCIM_GROUPS_PATH_PROPERTY = "picketlink.idm.realm.scim.groupsPath";
    public static final String SCIM_ROLES_PATH_PROPERTY = "picketlink.idm.realm.scim.rolesPath";

    public static final String PROVIDER_DOCUMENT = "document";
    public static final String PROVIDER_SCIM = "scim";
    public static final String DEFAULT_SCIM_CONTEXT_PATH = "/scim";
    public static final String DEFAULT_SCIM_USERS_PATH = "/Users";
    public static final String DEFAULT_SCIM_GROUPS_PATH = "/Groups";
    public static final String DEFAULT_SCIM_ROLES_PATH = "/Roles";

    private IdmRealmProviderConfig() {
    }

    public static String provider() {
        String override = System.getProperty(PROVIDER_PROPERTY);
        if (override != null && !override.isBlank()) {
            return override.trim().toLowerCase();
        }
        return fileConfig().getProvider();
    }

    public static boolean isScimProvider() {
        return PROVIDER_SCIM.equals(provider());
    }

    public static String scimBaseUrl() {
        String override = System.getProperty(SCIM_BASE_URL_PROPERTY);
        if (override != null && !override.isBlank()) {
            return trimTrailingSlash(override.trim());
        }
        IdmRealmConfigDocument config = fileConfig();
        if (config.getScimBaseUrl() != null && !config.getScimBaseUrl().isBlank()) {
            return trimTrailingSlash(config.getScimBaseUrl());
        }
        if (!useDefaultScimBaseUrl()) {
            throw new IllegalStateException("SCIM provider requires scimBaseUrl or useDefaultBaseUrl=true");
        }
        return trimTrailingSlash(resolveDefaultScimBaseUrl(scimContextPath()));
    }

    public static boolean useDefaultScimBaseUrl() {
        String override = System.getProperty(SCIM_USE_DEFAULT_BASE_URL_PROPERTY);
        if (override != null && !override.isBlank()) {
            return !"false".equalsIgnoreCase(override.trim());
        }
        return fileConfig().isUseDefaultBaseUrl();
    }

    public static String bearerToken() {
        String override = System.getProperty(SCIM_BEARER_TOKEN_PROPERTY);
        if (override != null) {
            return override.trim();
        }
        return fileConfig().getBearerToken();
    }

    public static boolean syncScimToDocument() {
        String override = System.getProperty(SCIM_SYNC_TO_DOCUMENT_PROPERTY);
        if (override != null && !override.isBlank()) {
            return !"false".equalsIgnoreCase(override.trim());
        }
        return fileConfig().isSyncToDocument();
    }

    public static String usersPath() {
        return normalizePath(readPathOverride(SCIM_USERS_PATH_PROPERTY, fileConfig().getUsersPath()));
    }

    public static String groupsPath() {
        return normalizePath(readPathOverride(SCIM_GROUPS_PATH_PROPERTY, fileConfig().getGroupsPath()));
    }

    public static String rolesPath() {
        return normalizePath(readPathOverride(SCIM_ROLES_PATH_PROPERTY, fileConfig().getRolesPath()));
    }

    public static String scimContextPath() {
        String override = System.getProperty(SCIM_CONTEXT_PATH_PROPERTY);
        if (override != null && !override.isBlank()) {
            return normalizePath(override.trim());
        }
        return normalizePath(fileConfig().getScimContextPath());
    }

    public static String resolveDefaultScimBaseUrl(String contextPath) {
        String host = System.getProperty("jboss.bind.address", "127.0.0.1");
        if ("0.0.0.0".equals(host) || "::".equals(host)) {
            host = "127.0.0.1";
        }
        String port = System.getProperty("jboss.http.port", "8080");
        return "http://" + host + ":" + port + normalizePath(contextPath);
    }

    public static String resolveEffectiveScimBaseUrl(IdmRealmConfigDocument config) {
        if (config.getScimBaseUrl() != null && !config.getScimBaseUrl().isBlank()) {
            return trimTrailingSlash(config.getScimBaseUrl());
        }
        if (config.isUseDefaultBaseUrl()) {
            return trimTrailingSlash(resolveDefaultScimBaseUrl(config.getScimContextPath()));
        }
        return "";
    }

    private static IdmRealmConfigDocument fileConfig() {
        try {
            return IdmRealmConfigService.global().current();
        } catch (java.io.IOException ex) {
            throw new IllegalStateException("Unable to load realm provider configuration", ex);
        }
    }

    private static String readPathOverride(String property, String fileDefault) {
        String override = System.getProperty(property);
        if (override != null && !override.isBlank()) {
            return override.trim();
        }
        return fileDefault;
    }

    static String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        return path.startsWith("/") ? path : "/" + path;
    }

    private static String trimTrailingSlash(String url) {
        if (url.endsWith("/") && url.length() > 1) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }
}
