package org.picketlink.auth.oauth.store;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.picketlink.auth.oauth.client.store.ClientRegistrationJsonCodec;
import org.picketlink.auth.oauth.client.store.ClientRegistrationStore;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * {@link ClientRegistrationStore} persisting the whole client registry as one JSON document
 * in a {@link JdbcClobDocumentStore} CLOB. Serialized access; concurrent writers get
 * {@link DocumentConcurrentUpdateException} through the store's optimistic locking.
 */
public final class JdbcClientRegistrationStore implements ClientRegistrationStore {

    public static final String DOCUMENT_ID = "clients";

    private final JsonDocumentStore documentStore;
    private final Object lock = new Object();

    public JdbcClientRegistrationStore(JsonDocumentStore documentStore) {
        this.documentStore = documentStore;
    }

    @Override
    public List<RegisteredClient> findAll() {
        String json = documentStore.load(DOCUMENT_ID);
        return ClientRegistrationJsonCodec.read(json);
    }

    @Override
    public Optional<RegisteredClient> findByClientId(String clientId) {
        for (RegisteredClient client : findAll()) {
            if (client.getClientId().equals(clientId)) {
                return Optional.of(client);
            }
        }
        return Optional.empty();
    }

    @Override
    public void save(RegisteredClient client) {
        synchronized (lock) {
            long version = documentStore.currentVersion(DOCUMENT_ID);
            List<RegisteredClient> clients = new ArrayList<>(findAll());
            removeClientId(clients, client.getClientId());
            clients.add(client);
            documentStore.save(DOCUMENT_ID, ClientRegistrationJsonCodec.write(clients), version);
        }
    }

    @Override
    public boolean delete(String clientId) {
        synchronized (lock) {
            long version = documentStore.currentVersion(DOCUMENT_ID);
            List<RegisteredClient> clients = findAll();
            boolean removed = containsClientId(clients, clientId);
            if (removed) {
                removeClientId(clients, clientId);
                documentStore.save(DOCUMENT_ID, ClientRegistrationJsonCodec.write(clients), version);
            }
            return removed;
        }
    }

    private static boolean containsClientId(List<RegisteredClient> clients, String clientId) {
        for (RegisteredClient existing : clients) {
            if (existing.getClientId().equals(clientId)) {
                return true;
            }
        }
        return false;
    }

    private static void removeClientId(List<RegisteredClient> clients, String clientId) {
        java.util.Iterator<RegisteredClient> it = clients.iterator();
        while (it.hasNext()) {
            if (it.next().getClientId().equals(clientId)) {
                it.remove();
            }
        }
    }
}
