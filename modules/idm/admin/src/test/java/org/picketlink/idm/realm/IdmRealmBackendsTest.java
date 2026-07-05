package org.picketlink.idm.realm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.picketlink.idm.document.IdmDocumentStores;
import org.picketlink.idm.realm.document.DocumentIdmRealmBackend;
import org.picketlink.idm.realm.scim.ScimIdmRealmBackend;

class IdmRealmBackendsTest {

    @AfterEach
    void reset() {
        IdmRealmBackends.resetForTests();
        IdmDocumentStores.resetForTests();
        org.picketlink.idm.realm.config.IdmRealmConfigStores.resetForTests();
        System.clearProperty(IdmRealmProviderConfig.PROVIDER_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_BASE_URL_PROPERTY);
        System.clearProperty(IdmRealmProviderConfig.SCIM_SYNC_TO_DOCUMENT_PROPERTY);
    }

    @Test
    void createsDocumentBackendByDefault() {
        assertInstanceOf(DocumentIdmRealmBackend.class, IdmRealmBackends.globalBackend());
        assertEquals(IdmRealmProviderConfig.PROVIDER_DOCUMENT, IdmRealmBackends.globalBackend().providerId());
    }

    @Test
    void createsScimBackendWhenConfigured() {
        System.setProperty(IdmRealmProviderConfig.PROVIDER_PROPERTY, IdmRealmProviderConfig.PROVIDER_SCIM);
        System.setProperty(IdmRealmProviderConfig.SCIM_BASE_URL_PROPERTY, "http://127.0.0.1:9999/scim");
        IdmRealmBackends.resetForTests();
        assertInstanceOf(ScimIdmRealmBackend.class, IdmRealmBackends.createBackend());
    }
}
