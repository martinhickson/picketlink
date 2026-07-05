package org.picketlink.auth.oauth.client.store;

import java.util.Optional;
import org.picketlink.auth.oauth.client.ClientRegistry;
import org.picketlink.auth.oauth.model.RegisteredClient;

public class PersistingClientRegistry implements ClientRegistry {

    private final ClientRegistrationStore store;

    public PersistingClientRegistry(ClientRegistrationStore store) {
        this.store = store;
    }

    @Override
    public Optional<RegisteredClient> findByClientId(String clientId) {
        return store.findByClientId(clientId);
    }

    @Override
    public void register(RegisteredClient client) {
        store.save(client);
    }

    public ClientRegistrationStore getStore() {
        return store;
    }
}
