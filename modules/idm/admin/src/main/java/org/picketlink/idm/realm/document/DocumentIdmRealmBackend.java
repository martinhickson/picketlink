package org.picketlink.idm.realm.document;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.picketlink.idm.credential.util.BCrypt;
import org.picketlink.idm.document.IdmDocumentStore;
import org.picketlink.idm.document.IdmRealmDocument;
import org.picketlink.idm.document.IdmRealmService;
import org.picketlink.idm.document.IdmUserRecord;
import org.picketlink.idm.document.OptimisticLockException;
import org.picketlink.idm.realm.IdmRealmBackend;
import org.picketlink.idm.realm.IdmRealmProviderConfig;
import org.picketlink.idm.realm.IdmRealmSnapshot;

public final class DocumentIdmRealmBackend implements IdmRealmBackend {

    private final IdmDocumentStore store;

    public DocumentIdmRealmBackend(IdmDocumentStore store) {
        this.store = store;
    }

    @Override
    public String providerId() {
        return IdmRealmProviderConfig.PROVIDER_DOCUMENT;
    }

    @Override
    public IdmRealmSnapshot loadRealm(String documentId) throws IOException {
        return toSnapshot(store.load(documentId));
    }

    @Override
    public Optional<IdmUserRecord> findUser(String documentId, String loginName) throws IOException {
        for (IdmUserRecord user : store.load(documentId).getUsers()) {
            if (loginName.equalsIgnoreCase(user.getLoginName())) {
                return Optional.of(user);
            }
        }
        return Optional.empty();
    }

    @Override
    public IdmRealmSnapshot createUser(String documentId, long expectedVersion, String loginName, String plainPassword,
            List<String> roles) throws IOException {
        IdmRealmDocument current = store.load(documentId);
        assertExpectedVersion(documentId, expectedVersion, current.getVersion());
        for (IdmUserRecord user : current.getUsers()) {
            if (loginName.equalsIgnoreCase(user.getLoginName())) {
                throw new IllegalArgumentException("User already exists: " + loginName);
            }
        }
        List<IdmUserRecord> users = new ArrayList<IdmUserRecord>(current.getUsers());
        users.add(IdmUserRecord.createNew(loginName, IdmRealmService.hashPassword(plainPassword), roles));
        IdmRealmDocument saved = store.save(current.nextVersion(users), expectedVersion);
        return toSnapshot(saved);
    }

    @Override
    public IdmRealmSnapshot updateUser(String documentId, long expectedVersion, String userId, String plainPassword,
            List<String> roles, Boolean enabled) throws IOException {
        IdmRealmDocument current = store.load(documentId);
        assertExpectedVersion(documentId, expectedVersion, current.getVersion());
        List<IdmUserRecord> users = new ArrayList<IdmUserRecord>();
        boolean found = false;
        for (IdmUserRecord user : current.getUsers()) {
            if (user.getId().equals(userId)) {
                found = true;
                IdmUserRecord updated = user;
                if (plainPassword != null && !plainPassword.isBlank()) {
                    updated = updated.withPasswordHash(IdmRealmService.hashPassword(plainPassword));
                }
                if (roles != null) {
                    updated = updated.withRoles(roles);
                }
                if (enabled != null) {
                    updated = updated.withEnabled(enabled);
                }
                users.add(updated);
            } else {
                users.add(user);
            }
        }
        if (!found) {
            throw new IllegalArgumentException("Unknown user id: " + userId);
        }
        IdmRealmDocument saved = store.save(current.nextVersion(users), expectedVersion);
        return toSnapshot(saved);
    }

    @Override
    public IdmRealmSnapshot deleteUser(String documentId, long expectedVersion, String userId) throws IOException {
        IdmRealmDocument current = store.load(documentId);
        assertExpectedVersion(documentId, expectedVersion, current.getVersion());
        List<IdmUserRecord> users = new ArrayList<IdmUserRecord>();
        boolean found = false;
        for (IdmUserRecord user : current.getUsers()) {
            if (user.getId().equals(userId)) {
                found = true;
            } else {
                users.add(user);
            }
        }
        if (!found) {
            throw new IllegalArgumentException("Unknown user id: " + userId);
        }
        IdmRealmDocument saved = store.save(current.nextVersion(users), expectedVersion);
        return toSnapshot(saved);
    }

    @Override
    public boolean verifyPassword(IdmUserRecord user, char[] password) {
        return BCrypt.checkpw(new String(password), user.getPasswordHash());
    }

    IdmDocumentStore store() {
        return store;
    }

    private static void assertExpectedVersion(String documentId, long expectedVersion, long actualVersion) {
        if (actualVersion != expectedVersion) {
            throw new OptimisticLockException(documentId, expectedVersion, actualVersion);
        }
    }

    private IdmRealmSnapshot toSnapshot(IdmRealmDocument document) {
        Set<String> roles = new LinkedHashSet<String>();
        for (IdmUserRecord user : document.getUsers()) {
            roles.addAll(user.getRoles());
        }
        return new IdmRealmSnapshot(
                document.getDocumentId(),
                document.getVersion(),
                providerId(),
                null,
                document.getUsers(),
                new ArrayList<String>(roles),
                List.of());
    }
}
