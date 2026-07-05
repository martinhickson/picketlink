package org.picketlink.auth.oauth.service;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientAuthentication;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.model.AccessTokenRecord;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.token.AccessTokenGenerator;
import org.picketlink.auth.oauth.token.AccessTokenRegistry;

public class ClientCredentialsTokenService {

    private final ClientCredentialsAuthenticator authenticator;
    private final AccessTokenGenerator tokenGenerator;
    private final AccessTokenRegistry tokenRegistry;
    private final Clock clock;
    private long accessTokenLifetimeSeconds = 3600L;

    public ClientCredentialsTokenService(ClientCredentialsAuthenticator authenticator,
            AccessTokenGenerator tokenGenerator,
            AccessTokenRegistry tokenRegistry) {
        this(authenticator, tokenGenerator, tokenRegistry, Clock.systemUTC());
    }

    public ClientCredentialsTokenService(ClientCredentialsAuthenticator authenticator,
            AccessTokenGenerator tokenGenerator,
            AccessTokenRegistry tokenRegistry,
            Clock clock) {
        this.authenticator = authenticator;
        this.tokenGenerator = tokenGenerator;
        this.tokenRegistry = tokenRegistry;
        this.clock = clock;
    }

    public TokenResponse issueToken(TokenRequest request) {
        validateGrantType(request.getGrantType());
        ClientAuthentication authentication = authenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();
        Set<String> approvedScopes = ScopeValidator.resolveApprovedScopes(client, request.getScope());

        Instant issuedAt = clock.instant();
        Instant expiresAt = issuedAt.plusSeconds(accessTokenLifetimeSeconds);
        String tokenValue = tokenGenerator.generate();

        AccessTokenRecord record = new AccessTokenRecord(
                tokenValue,
                client.getClientId(),
                approvedScopes,
                issuedAt,
                expiresAt);
        tokenRegistry.store(record);

        String scope = ScopeValidator.formatScope(approvedScopes);
        return new TokenResponse(
                tokenValue,
                OAuthConstants.BEARER_TOKEN_TYPE,
                accessTokenLifetimeSeconds,
                scope);
    }

    public long getAccessTokenLifetimeSeconds() {
        return accessTokenLifetimeSeconds;
    }

    public void setAccessTokenLifetimeSeconds(long accessTokenLifetimeSeconds) {
        if (accessTokenLifetimeSeconds <= 0) {
            throw new IllegalArgumentException("accessTokenLifetimeSeconds must be positive");
        }
        this.accessTokenLifetimeSeconds = accessTokenLifetimeSeconds;
    }

    protected ClientCredentialsAuthenticator getAuthenticator() {
        return authenticator;
    }

    protected Clock getServiceClock() {
        return clock;
    }

    private static void validateGrantType(String grantType) {
        if (grantType == null || grantType.isBlank()) {
            throw new OAuthException(
                    new OAuthErrorResponse(OAuthConstants.INVALID_REQUEST, "grant_type is required"),
                    400);
        }
        if (!OAuthConstants.CLIENT_CREDENTIALS_GRANT.equals(grantType)) {
            throw new OAuthException(
                    new OAuthErrorResponse(OAuthConstants.UNSUPPORTED_GRANT_TYPE,
                            "Only client_credentials is supported"),
                    400);
        }
    }
}
