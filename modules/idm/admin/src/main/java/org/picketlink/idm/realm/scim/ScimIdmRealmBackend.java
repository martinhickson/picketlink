package org.picketlink.idm.realm.scim;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.picketlink.idm.document.IdmUserRecord;
import org.picketlink.idm.realm.IdmRealmBackend;
import org.picketlink.idm.realm.IdmRealmProviderConfig;
import org.picketlink.idm.realm.IdmRealmSnapshot;
import org.picketlink.idm.realm.document.DocumentIdmRealmBackend;

public final class ScimIdmRealmBackend implements IdmRealmBackend {

    private final ScimRealmClient scimClient;
    private final String scimBaseUrl;
    private final DocumentIdmRealmBackend documentBackend;
    private final boolean syncToDocument;

    public ScimIdmRealmBackend(ScimRealmClient scimClient, String scimBaseUrl, DocumentIdmRealmBackend documentBackend,
            boolean syncToDocument) {
        this.scimClient = scimClient;
        this.scimBaseUrl = scimBaseUrl;
        this.documentBackend = documentBackend;
        this.syncToDocument = syncToDocument;
    }

    @Override
    public String providerId() {
        return IdmRealmProviderConfig.PROVIDER_SCIM;
    }

    @Override
    public IdmRealmSnapshot loadRealm(String documentId) throws IOException {
        List<ScimRealmClient.ScimResource> users = scimClient.listUsers();
        List<ScimRealmClient.ScimResource> groups = scimClient.listGroups();
        List<ScimRealmClient.ScimResource> roles = scimClient.listRoles();
        return new IdmRealmSnapshot(
                documentId,
                0L,
                providerId(),
                scimBaseUrl,
                mapUsers(users, roles),
                ScimRealmClient.roleNames(roles),
                ScimRealmClient.groupNames(groups));
    }

    @Override
    public Optional<IdmUserRecord> findUser(String documentId, String loginName) throws IOException {
        Optional<IdmUserRecord> local = documentBackend.findUser(documentId, loginName);
        if (local.isPresent()) {
            return local;
        }
        for (IdmUserRecord user : loadRealm(documentId).getUsers()) {
            if (loginName.equalsIgnoreCase(user.getLoginName())) {
                return Optional.of(user);
            }
        }
        return Optional.empty();
    }

    @Override
    public IdmRealmSnapshot createUser(String documentId, long expectedVersion, String loginName, String plainPassword,
            List<String> roles) throws IOException {
        scimClient.createUser(loginName, plainPassword, true, roles);
        if (syncToDocument) {
            try {
                documentBackend.createUser(documentId, documentVersion(documentId), loginName, plainPassword, roles);
            } catch (RuntimeException ex) {
                // Keep SCIM as source of truth even if local credential sync fails.
            }
        }
        return loadRealm(documentId);
    }

    @Override
    public IdmRealmSnapshot updateUser(String documentId, long expectedVersion, String userId, String plainPassword,
            List<String> roles, Boolean enabled) throws IOException {
        scimClient.updateUser(userId, plainPassword, enabled, roles);
        if (syncToDocument) {
            try {
                documentBackend.updateUser(documentId, documentVersion(documentId), userId, plainPassword, roles, enabled);
            } catch (RuntimeException ex) {
                // Keep SCIM as source of truth even if local credential sync fails.
            }
        }
        return loadRealm(documentId);
    }

    @Override
    public IdmRealmSnapshot deleteUser(String documentId, long expectedVersion, String userId) throws IOException {
        scimClient.deleteUser(userId);
        if (syncToDocument) {
            try {
                for (IdmUserRecord localUser : documentBackend.loadRealm(documentId).getUsers()) {
                    if (localUser.getId().equals(userId)) {
                        documentBackend.deleteUser(documentId, documentVersion(documentId), localUser.getId());
                        break;
                    }
                }
            } catch (RuntimeException ex) {
                // Keep SCIM as source of truth even if local credential sync fails.
            }
        }
        return loadRealm(documentId);
    }

    @Override
    public boolean verifyPassword(IdmUserRecord user, char[] password) {
        return documentBackend.verifyPassword(user, password);
    }

    private long documentVersion(String documentId) throws IOException {
        return documentBackend.loadRealm(documentId).getVersion();
    }

    private static List<IdmUserRecord> mapUsers(List<ScimRealmClient.ScimResource> users,
            List<ScimRealmClient.ScimResource> roles) {
        List<IdmUserRecord> mapped = new ArrayList<IdmUserRecord>();
        for (ScimRealmClient.ScimResource user : users) {
            List<String> userRoles = user.getGroups().isEmpty() ? List.of("role1") : user.getGroups();
            mapped.add(new IdmUserRecord(
                    user.getId(),
                    user.loginName(),
                    "",
                    userRoles,
                    user.isActive()));
        }
        return mapped;
    }
}
