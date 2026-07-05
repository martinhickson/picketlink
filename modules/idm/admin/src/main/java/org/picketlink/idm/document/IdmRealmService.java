package org.picketlink.idm.document;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.picketlink.idm.realm.IdmRealmBackend;
import org.picketlink.idm.realm.IdmRealmBackends;
import org.picketlink.idm.realm.IdmRealmSnapshot;

public final class IdmRealmService {

    private final IdmRealmBackend fixedBackend;

    public IdmRealmService(IdmDocumentStore store) {
        this(new org.picketlink.idm.realm.document.DocumentIdmRealmBackend(store));
    }

    public IdmRealmService(IdmRealmBackend backend) {
        this.fixedBackend = backend;
    }

    public IdmRealmService() {
        this.fixedBackend = null;
    }

    public IdmRealmSnapshot loadRealmSnapshot(String documentId) throws IOException {
        return backend().loadRealm(documentId);
    }

    public IdmRealmDocument loadRealm(String documentId) throws IOException {
        return toDocument(backend().loadRealm(documentId));
    }

    public List<IdmUserRecord> listUsers(String documentId) throws IOException {
        return backend().loadRealm(documentId).getUsers();
    }

    public Optional<IdmUserRecord> findUser(String documentId, String loginName) throws IOException {
        return backend().findUser(documentId, loginName);
    }

    public IdmRealmSnapshot createUserSnapshot(String documentId, long expectedVersion, String loginName,
            String plainPassword, List<String> roles) throws IOException {
        return backend().createUser(documentId, expectedVersion, loginName, plainPassword, roles);
    }

    public IdmRealmSnapshot updateUserSnapshot(String documentId, long expectedVersion, String userId,
            String plainPassword, List<String> roles, Boolean enabled) throws IOException {
        return backend().updateUser(documentId, expectedVersion, userId, plainPassword, roles, enabled);
    }

    public IdmRealmSnapshot deleteUserSnapshot(String documentId, long expectedVersion, String userId)
            throws IOException {
        return backend().deleteUser(documentId, expectedVersion, userId);
    }

    public IdmRealmDocument createUser(String documentId, long expectedVersion, String loginName,
            String plainPassword, List<String> roles) throws IOException {
        return toDocument(backend().createUser(documentId, expectedVersion, loginName, plainPassword, roles));
    }

    public IdmRealmDocument updateUser(String documentId, long expectedVersion, String userId,
            String plainPassword, List<String> roles, Boolean enabled) throws IOException {
        return toDocument(backend().updateUser(documentId, expectedVersion, userId, plainPassword, roles, enabled));
    }

    public IdmRealmDocument deleteUser(String documentId, long expectedVersion, String userId) throws IOException {
        return toDocument(backend().deleteUser(documentId, expectedVersion, userId));
    }

    public boolean verifyPassword(IdmUserRecord user, char[] password) {
        return backend().verifyPassword(user, password);
    }

    public static String hashPassword(String plainPassword) {
        return org.picketlink.idm.credential.util.BCrypt.hashpw(plainPassword, org.picketlink.idm.credential.util.BCrypt.gensalt());
    }

    IdmRealmBackend backend() {
        return fixedBackend != null ? fixedBackend : IdmRealmBackends.globalBackend();
    }

    private static IdmRealmDocument toDocument(IdmRealmSnapshot snapshot) {
        return new IdmRealmDocument(snapshot.getDocumentId(), snapshot.getVersion(), snapshot.getUsers());
    }
}
