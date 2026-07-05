package org.picketlink.idm.realm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class IdmRealmProviderConfigTest {

    @AfterEach
    void clearProperties() {
        System.clearProperty(IdmRealmProviderConfig.PROVIDER_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_BASE_URL_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_USE_DEFAULT_BASE_URL_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_CONTEXT_PATH_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_BEARER_TOKEN_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_SYNC_TO_DOCUMENT_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_USERS_PATH_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_GROUPS_PATH_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_ROLES_PATH_PROPERTY);
        System.clearProperty("jboss.bind.address");
        System.clearProperty("jboss.http.port");
        System.clearProperty("picketlink.idm.realm.config.file");
        org.picketlink.idm.realm.config.IdmRealmConfigStores.resetForTests();
        org.picketlink.idm.realm.IdmRealmBackends.resetForTests();
    }

    @Test
    void defaultsToDocumentProvider() {
        assertEquals(IdmRealmProviderConfig.PROVIDER_DOCUMENT, IdmRealmProviderConfig.provider());
        assertFalse(IdmRealmProviderConfig.isScimProvider());
    }

    @Test
    void resolvesExplicitScimBaseUrl() {
        System.setProperty(IdmRealmProviderConfig.PROVIDER_PROPERTY, IdmRealmProviderConfig.PROVIDER_SCIM);
        System.setProperty(IdmRealmProviderConfig.SCIM_BASE_URL_PROPERTY, "https://idp.example.com/scim/");
        assertTrue(IdmRealmProviderConfig.isScimProvider());
        assertEquals("https://idp.example.com/scim", IdmRealmProviderConfig.scimBaseUrl());
    }

    @Test
    void resolvesDefaultWildFlyScimBaseUrl() {
        System.setProperty(IdmRealmProviderConfig.PROVIDER_PROPERTY, IdmRealmProviderConfig.PROVIDER_SCIM);
        System.setProperty("jboss.bind.address", "0.0.0.0");
        System.setProperty("jboss.http.port", "8180");
        System.setProperty(IdmRealmProviderConfig.SCIM_CONTEXT_PATH_PROPERTY, "/custom-scim");
        assertEquals("http://127.0.0.1:8180/custom-scim", IdmRealmProviderConfig.scimBaseUrl());
    }

    @Test
    void requiresExplicitBaseUrlWhenDefaultDisabled() {
        System.setProperty(IdmRealmProviderConfig.PROVIDER_PROPERTY, IdmRealmProviderConfig.PROVIDER_SCIM);
        System.setProperty(IdmRealmProviderConfig.SCIM_USE_DEFAULT_BASE_URL_PROPERTY, "false");
        assertThrows(IllegalStateException.class, IdmRealmProviderConfig::scimBaseUrl);
    }

    @Test
    void readsProviderFromConfigFile(@org.junit.jupiter.api.io.TempDir Path tempDir) throws Exception {
        System.setProperty("picketlink.idm.realm.config.file", tempDir.resolve("cfg.json").toString());
        org.picketlink.idm.realm.config.IdmRealmConfigStores.resetForTests();
        new org.picketlink.idm.realm.config.JsonFileIdmRealmConfigStore(tempDir.resolve("cfg.json"))
                .save(new org.picketlink.idm.realm.config.IdmRealmConfigDocument(
                        IdmRealmProviderConfig.PROVIDER_SCIM,
                        "http://127.0.0.1:9090/scim",
                        false,
                        "/scim",
                        "token",
                        false,
                        "/Users",
                        "/Groups",
                        "/Roles"));
        assertEquals(IdmRealmProviderConfig.PROVIDER_SCIM, IdmRealmProviderConfig.provider());
        assertEquals("http://127.0.0.1:9090/scim", IdmRealmProviderConfig.scimBaseUrl());
    }

    @Test
    void normalizesScimPathsAndToken() {
        System.setProperty(IdmRealmProviderConfig.SCIM_USERS_PATH_PROPERTY, "Users");
        System.setProperty(IdmRealmProviderConfig.SCIM_GROUPS_PATH_PROPERTY, "Groups");
        System.setProperty(IdmRealmProviderConfig.SCIM_ROLES_PATH_PROPERTY, "Roles");
        System.setProperty(IdmRealmProviderConfig.SCIM_BEARER_TOKEN_PROPERTY, "  secret  ");
        System.setProperty(IdmRealmProviderConfig.SCIM_SYNC_TO_DOCUMENT_PROPERTY, "false");
        assertEquals("/Users", IdmRealmProviderConfig.usersPath());
        assertEquals("/Groups", IdmRealmProviderConfig.groupsPath());
        assertEquals("/Roles", IdmRealmProviderConfig.rolesPath());
        assertEquals("secret", IdmRealmProviderConfig.bearerToken());
        assertFalse(IdmRealmProviderConfig.syncScimToDocument());
    }
}
