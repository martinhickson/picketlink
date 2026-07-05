package org.picketlink.idm.realm;

import org.picketlink.idm.document.IdmDocumentStores;
import org.picketlink.idm.realm.document.DocumentIdmRealmBackend;
import org.picketlink.idm.realm.scim.ScimIdmRealmBackend;
import org.picketlink.idm.realm.scim.ScimRealmClient;

public final class IdmRealmBackends {

    private static volatile IdmRealmBackend globalBackend;

    private IdmRealmBackends() {
    }

    public static IdmRealmBackend globalBackend() {
        IdmRealmBackend current = globalBackend;
        if (current == null) {
            synchronized (IdmRealmBackends.class) {
                current = globalBackend;
                if (current == null) {
                    current = createBackend();
                    globalBackend = current;
                }
            }
        }
        return current;
    }

    public static void resetForTests() {
        globalBackend = null;
    }

    public static IdmRealmBackend createBackend() {
        DocumentIdmRealmBackend documentBackend = new DocumentIdmRealmBackend(IdmDocumentStores.globalStore());
        if (IdmRealmProviderConfig.isScimProvider()) {
            ScimRealmClient client = new ScimRealmClient(
                    IdmRealmProviderConfig.scimBaseUrl(),
                    IdmRealmProviderConfig.bearerToken(),
                    IdmRealmProviderConfig.usersPath(),
                    IdmRealmProviderConfig.groupsPath(),
                    IdmRealmProviderConfig.rolesPath());
            return new ScimIdmRealmBackend(
                    client,
                    IdmRealmProviderConfig.scimBaseUrl(),
                    documentBackend,
                    IdmRealmProviderConfig.syncScimToDocument());
        }
        return documentBackend;
    }
}
