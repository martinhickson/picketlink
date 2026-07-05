package org.picketlink.auth.oauth.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.client.ClientRegistry;
import org.picketlink.auth.oauth.client.ClientSecretMatcher;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.model.TokenRequest;

public class ClientCredentialsAuthenticator {

    private final ClientRegistry clientRegistry;
    private final ClientSecretMatcher secretMatcher;

    public ClientCredentialsAuthenticator(ClientRegistry clientRegistry, ClientSecretMatcher secretMatcher) {
        this.clientRegistry = clientRegistry;
        this.secretMatcher = secretMatcher;
    }

    public ClientAuthentication authenticate(TokenRequest request) {
        String authorizationHeader = request.getAuthorizationHeader();
        if (authorizationHeader != null && authorizationHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            return authenticateBasic(authorizationHeader.substring(6).trim(), request);
        }

        String clientId = request.getFormParameter(OAuthConstants.CLIENT_ID);
        String clientSecret = request.getFormParameter(OAuthConstants.CLIENT_SECRET);
        if (clientId != null && clientSecret != null) {
            return authenticateWithSecret(clientId, clientSecret, TokenEndpointAuthMethod.CLIENT_SECRET_POST);
        }

        throw invalidClient("Client authentication failed");
    }

    private ClientAuthentication authenticateBasic(String encodedCredentials, TokenRequest request) {
        String[] credentials = decodeBasicCredentials(encodedCredentials);
        String clientId = credentials[0];
        String clientSecret = credentials[1];

        String bodyClientId = request.getFormParameter(OAuthConstants.CLIENT_ID);
        if (bodyClientId != null && !bodyClientId.equals(clientId)) {
            throw invalidClient("client_id in request body does not match Authorization header");
        }

        return authenticateWithSecret(clientId, clientSecret, TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
    }

    private ClientAuthentication authenticateWithSecret(String clientId, String clientSecret,
            TokenEndpointAuthMethod authMethod) {
        Optional<RegisteredClient> registeredClient = clientRegistry.findByClientId(clientId);
        if (!registeredClient.isPresent()) {
            throw invalidClient("Unknown client");
        }
        RegisteredClient client = registeredClient.get();

        if (!secretMatcher.matches(client.getClientSecret(), clientSecret)) {
            throw invalidClient("Invalid client credentials");
        }

        if (client.getTokenEndpointAuthMethod() != authMethod) {
            throw invalidClient("Client authentication method mismatch");
        }

        return new ClientAuthentication(client, authMethod);
    }

    private static String[] decodeBasicCredentials(String encodedCredentials) {
        try {
            String decoded = new String(Base64.getDecoder().decode(encodedCredentials), StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 0) {
                throw invalidClient("Malformed Basic Authorization header");
            }
            return new String[] {
                    decoded.substring(0, separator),
                    decoded.substring(separator + 1)
            };
        } catch (IllegalArgumentException ex) {
            throw invalidClient("Malformed Basic Authorization header");
        }
    }

    private static OAuthException invalidClient(String description) {
        return new OAuthException(new OAuthErrorResponse(OAuthConstants.INVALID_CLIENT, description), 401);
    }
}
