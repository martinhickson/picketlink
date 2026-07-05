package org.picketlink.auth.oauth.client.store;

import java.util.List;
import java.util.Optional;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * Pluggable persistence for OAuth client registrations.
 * Default implementation stores JSON on the filesystem; other implementations
 * may use a database CLOB, LDAP, etc.
 */
public interface ClientRegistrationStore {

    List<RegisteredClient> findAll();

    Optional<RegisteredClient> findByClientId(String clientId);

    void save(RegisteredClient client);

    boolean delete(String clientId);
}
