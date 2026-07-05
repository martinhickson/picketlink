package org.picketlink.auth.oauth.client;

import java.util.Optional;
import org.picketlink.auth.oauth.model.RegisteredClient;

public interface ClientRegistry {

    Optional<RegisteredClient> findByClientId(String clientId);

    void register(RegisteredClient client);
}
