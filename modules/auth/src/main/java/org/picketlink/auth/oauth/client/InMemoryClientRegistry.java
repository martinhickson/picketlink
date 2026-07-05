package org.picketlink.auth.oauth.client;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.picketlink.auth.oauth.model.RegisteredClient;

public class InMemoryClientRegistry implements ClientRegistry {

    private final Map<String, RegisteredClient> clients = new ConcurrentHashMap<>();

    @Override
    public Optional<RegisteredClient> findByClientId(String clientId) {
        if (clientId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(clients.get(clientId));
    }

    @Override
    public void register(RegisteredClient client) {
        clients.put(client.getClientId(), client);
    }
}
