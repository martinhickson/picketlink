package org.picketlink.auth.cxf;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.provider.AbstractOAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.tokens.refresh.RefreshToken;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.picketlink.auth.oauth.client.ClientRegistry;
import org.picketlink.auth.oauth.model.AccessTokenRecord;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.token.AccessTokenRegistry;

public class ClientCredentialsOAuthDataProvider extends AbstractOAuthDataProvider {

    private final ClientRegistry clientRegistry;
    private final AccessTokenRegistry accessTokenRegistry;

    public ClientCredentialsOAuthDataProvider(ClientRegistry clientRegistry,
            AccessTokenRegistry accessTokenRegistry) {
        this.clientRegistry = clientRegistry;
        this.accessTokenRegistry = accessTokenRegistry;
    }

    @Override
    public List<Client> getClients(UserSubject resourceOwner) {
        return Collections.emptyList();
    }

    @Override
    protected Client doGetClient(String clientId) throws OAuthServiceException {
        Optional<RegisteredClient> registeredClient = clientRegistry.findByClientId(clientId);
        if (registeredClient.isPresent()) {
            return toCxfClient(registeredClient.get());
        }
        return null;
    }

    @Override
    public void setClient(Client client) {
        clientRegistry.register(toRegisteredClient(client));
    }

    @Override
    protected void doRemoveClient(Client client) {
        // Client removal is delegated to custom ClientRegistry implementations.
    }

    @Override
    protected void saveAccessToken(ServerAccessToken serverToken) {
        Instant issuedAt = Instant.ofEpochSecond(serverToken.getIssuedAt());
        Instant expiresAt = issuedAt.plusSeconds(serverToken.getExpiresIn());
        List<String> scopes = new ArrayList<>();
        if (serverToken.getScopes() != null) {
            for (OAuthPermission permission : serverToken.getScopes()) {
                scopes.add(permission.getPermission());
            }
        }
        accessTokenRegistry.store(new AccessTokenRecord(
                serverToken.getTokenKey(),
                serverToken.getClient().getClientId(),
                new java.util.LinkedHashSet<String>(scopes),
                issuedAt,
                expiresAt));
    }

    @Override
    public ServerAccessToken getAccessToken(String accessToken) throws OAuthServiceException {
        Optional<AccessTokenRecord> record = accessTokenRegistry.findByTokenValue(accessToken);
        if (record.isPresent()) {
            return toServerAccessToken(record.get());
        }
        return null;
    }

    @Override
    public List<ServerAccessToken> getAccessTokens(Client client, UserSubject subject)
            throws OAuthServiceException {
        return Collections.emptyList();
    }

    @Override
    public List<RefreshToken> getRefreshTokens(Client client, UserSubject subject)
            throws OAuthServiceException {
        return Collections.emptyList();
    }

    @Override
    protected void saveRefreshToken(RefreshToken refreshToken) {
        // Refresh tokens are not issued for client_credentials.
    }

    @Override
    protected void doRevokeAccessToken(ServerAccessToken accessToken) {
        accessTokenRegistry.remove(accessToken.getTokenKey());
    }

    @Override
    protected void doRevokeRefreshToken(RefreshToken refreshToken) {
        // Refresh tokens are not issued for client_credentials.
    }

    @Override
    protected RefreshToken getRefreshToken(String refreshTokenKey) {
        return null;
    }

    private ServerAccessToken toServerAccessToken(AccessTokenRecord record) {
        Optional<RegisteredClient> registeredClient = clientRegistry.findByClientId(record.getClientId());
        if (!registeredClient.isPresent()) {
            throw new OAuthServiceException("Unknown token client");
        }
        Client client = toCxfClient(registeredClient.get());
        ServerAccessToken token = createNewAccessToken(client, null);
        token.setTokenKey(record.getTokenValue());
        token.setIssuedAt(record.getIssuedAt().getEpochSecond());
        token.setExpiresIn(record.getExpiresAt().getEpochSecond() - record.getIssuedAt().getEpochSecond());
        token.setGrantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT);
        List<OAuthPermission> permissions = new ArrayList<>();
        for (String scope : record.getScopes()) {
            permissions.add(new OAuthPermission(scope, scope));
        }
        token.setScopes(permissions);
        return token;
    }

    private static Client toCxfClient(RegisteredClient registeredClient) {
        Client client = new Client(
                registeredClient.getClientId(),
                registeredClient.getClientSecret(),
                true);
        client.setAllowedGrantTypes(Collections.singletonList(OAuthConstants.CLIENT_CREDENTIALS_GRANT));
        client.setRegisteredScopes(new ArrayList<String>(registeredClient.getScopes()));
        client.setTokenEndpointAuthMethod(registeredClient.getTokenEndpointAuthMethod().getValue());
        return client;
    }

    private static RegisteredClient toRegisteredClient(Client client) {
        RegisteredClient.Builder builder = RegisteredClient.builder(
                client.getClientId(),
                client.getClientSecret());
        if (client.getRegisteredScopes() != null) {
            builder.scopes(new java.util.LinkedHashSet<String>(client.getRegisteredScopes()));
        }
        if (OAuthConstants.TOKEN_ENDPOINT_AUTH_POST.equals(client.getTokenEndpointAuthMethod())) {
            builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST);
        } else {
            builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
        }
        return builder.build();
    }
}
