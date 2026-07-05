package org.picketlink.auth.oauth.admin;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.client.store.ClientRegistrationStore;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.token.AccessTokenGenerator;

public class ClientRegistrationService {

    private final ClientRegistrationStore store;
    private final AccessTokenGenerator secretGenerator;

    public ClientRegistrationService(ClientRegistrationStore store) {
        this(store, new AccessTokenGenerator(24));
    }

    public ClientRegistrationService(ClientRegistrationStore store, AccessTokenGenerator secretGenerator) {
        this.store = store;
        this.secretGenerator = secretGenerator;
    }

    public List<ClientRegistrationView> listClients() {
        List<ClientRegistrationView> views = new ArrayList<ClientRegistrationView>();
        for (RegisteredClient client : store.findAll()) {
            views.add(toView(client, false));
        }
        return views;
    }

    public ClientRegistrationView registerClient(ClientRegistrationRequest request) {
        validateRequest(request);
        if (store.findByClientId(request.getClientId()).isPresent()) {
            throw new ClientRegistrationException("Client already exists: " + request.getClientId());
        }
        String secret = request.getClientSecret();
        if (secret == null || secret.isBlank()) {
            secret = secretGenerator.generate();
        }
        RegisteredClient client = RegisteredClient.builder(request.getClientId().trim(), secret)
                .scopes(parseScopes(request.getScopes()))
                .tokenEndpointAuthMethod(resolveAuthMethod(request.getTokenEndpointAuthMethod()))
                .build();
        store.save(client);
        return toView(client, true);
    }

    public boolean deleteClient(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return false;
        }
        return store.delete(clientId.trim());
    }

    private static void validateRequest(ClientRegistrationRequest request) {
        if (request == null) {
            throw new ClientRegistrationException("Request body is required");
        }
        if (request.getClientId() == null || request.getClientId().isBlank()) {
            throw new ClientRegistrationException("clientId is required");
        }
    }

    private static Set<String> parseScopes(List<String> scopes) {
        Set<String> values = new LinkedHashSet<String>();
        if (scopes != null) {
            for (String scope : scopes) {
                if (scope != null && !scope.isBlank()) {
                    values.add(scope.trim());
                }
            }
        }
        return values;
    }

    private static TokenEndpointAuthMethod resolveAuthMethod(String value) {
        if (OAuthConstants.TOKEN_ENDPOINT_AUTH_POST.equals(value)) {
            return TokenEndpointAuthMethod.CLIENT_SECRET_POST;
        }
        return TokenEndpointAuthMethod.CLIENT_SECRET_BASIC;
    }

    private static ClientRegistrationView toView(RegisteredClient client, boolean includeSecret) {
        ClientRegistrationView view = new ClientRegistrationView();
        view.setClientId(client.getClientId());
        view.setScopes(new ArrayList<String>(client.getScopes()));
        view.setTokenEndpointAuthMethod(client.getTokenEndpointAuthMethod().getValue());
        if (includeSecret) {
            view.setClientSecret(client.getClientSecret());
        } else {
            view.setClientSecret("********");
        }
        return view;
    }
}
