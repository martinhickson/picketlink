package org.picketlink.auth.oauth.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.client.ClientRegistry;
import org.picketlink.auth.oauth.client.ClientSecretMatcher;
import org.picketlink.auth.oauth.issuance.ClientAssertionValidator;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.model.TokenRequest;

public class ClientCredentialsAuthenticator {

    private final ClientRegistry clientRegistry;
    private final ClientSecretMatcher secretMatcher;
    private final ClientAssertionValidator clientAssertionValidator;

    public ClientCredentialsAuthenticator(ClientRegistry clientRegistry, ClientSecretMatcher secretMatcher) {
        this(clientRegistry, secretMatcher, null);
    }

    public ClientCredentialsAuthenticator(ClientRegistry clientRegistry,
            ClientSecretMatcher secretMatcher,
            ClientAssertionValidator clientAssertionValidator) {
        this.clientRegistry = clientRegistry;
        this.secretMatcher = secretMatcher;
        this.clientAssertionValidator = clientAssertionValidator;
    }

    public ClientAuthentication authenticate(TokenRequest request) {
        String assertionType = request.getFormParameter(OAuthConstants.CLIENT_ASSERTION_TYPE);
        String assertion = request.getFormParameter(OAuthConstants.CLIENT_ASSERTION);
        if (assertionType != null || assertion != null) {
            return authenticateWithAssertion(assertionType, assertion);
        }

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

    /** RFC 7523 {@code private_key_jwt} client authentication for automated REST clients. */
    private ClientAuthentication authenticateWithAssertion(String assertionType, String assertion) {
        if (clientAssertionValidator == null) {
            throw invalidClient("JWT client authentication is not enabled on this server");
        }
        if (!OAuthConstants.JWT_BEARER_CLIENT_ASSERTION_TYPE.equals(assertionType)) {
            throw invalidClient("Unsupported client_assertion_type");
        }
        if (assertion == null || assertion.isBlank()) {
            throw invalidClient("client_assertion is required");
        }

        String clientId = clientAssertionValidator.readIssuer(assertion);
        Optional<RegisteredClient> registered = clientRegistry.findByClientId(clientId);
        if (!registered.isPresent()) {
            throw invalidClient("Unknown client");
        }
        RegisteredClient client = registered.get();
        if (client.getTokenEndpointAuthMethod() != TokenEndpointAuthMethod.PRIVATE_KEY_JWT) {
            throw invalidClient("Client is not registered for private_key_jwt authentication");
        }
        clientAssertionValidator.validate(assertion, client);
        return new ClientAuthentication(client, TokenEndpointAuthMethod.PRIVATE_KEY_JWT);
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

        if (client.getClientSecret() == null
                || !secretMatcher.matches(client.getClientSecret(), clientSecret)) {
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
