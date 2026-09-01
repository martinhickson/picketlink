package org.picketlink.auth.oauth.client.store;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.picketlink.auth.oauth.model.RegisteredClient;

/** Non-persistent {@link ClientRegistrationStore}; default when no file or JDBC store is configured. */
public final class InMemoryClientRegistrationStore implements ClientRegistrationStore {

    private final List<RegisteredClient> clients = new ArrayList<>();

    @Override
    public List<RegisteredClient> findAll() {
        return new ArrayList<>(clients);
    }

    @Override
    public Optional<RegisteredClient> findByClientId(String clientId) {
        for (RegisteredClient client : clients) {
            if (client.getClientId().equals(clientId)) {
                return Optional.of(client);
            }
        }
        return Optional.empty();
    }

    @Override
    public void save(RegisteredClient client) {
        java.util.Iterator<RegisteredClient> it = clients.iterator();
        while (it.hasNext()) {
            if (it.next().getClientId().equals(client.getClientId())) {
                it.remove();
            }
        }
        clients.add(client);
    }

    @Override
    public boolean delete(String clientId) {
        java.util.Iterator<RegisteredClient> it = clients.iterator();
        while (it.hasNext()) {
            if (it.next().getClientId().equals(clientId)) {
                it.remove();
                return true;
            }
        }
        return false;
    }
}
