package org.picketlink.idm.realm;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.picketlink.idm.document.IdmUserRecord;

/**
 * Pluggable realm backend for admin UI and Elytron authentication.
 */
public interface IdmRealmBackend {

    String providerId();

    IdmRealmSnapshot loadRealm(String documentId) throws IOException;

    Optional<IdmUserRecord> findUser(String documentId, String loginName) throws IOException;

    IdmRealmSnapshot createUser(String documentId, long expectedVersion, String loginName, String plainPassword,
            List<String> roles) throws IOException;

    IdmRealmSnapshot updateUser(String documentId, long expectedVersion, String userId, String plainPassword,
            List<String> roles, Boolean enabled) throws IOException;

    IdmRealmSnapshot deleteUser(String documentId, long expectedVersion, String userId) throws IOException;

    boolean verifyPassword(IdmUserRecord user, char[] password);
}
