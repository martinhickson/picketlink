package org.picketlink.auth.oauth.auth;

import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;

public final class ClientAuthentication {

    private final RegisteredClient client;
    private final TokenEndpointAuthMethod authMethod;

    public ClientAuthentication(RegisteredClient client, TokenEndpointAuthMethod authMethod) {
        this.client = client;
        this.authMethod = authMethod;
    }

    public RegisteredClient getClient() {
        return client;
    }

    public TokenEndpointAuthMethod getAuthMethod() {
        return authMethod;
    }
}
