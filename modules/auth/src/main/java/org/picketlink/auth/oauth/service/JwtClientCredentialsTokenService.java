package org.picketlink.auth.oauth.service;

import java.time.Clock;
import java.util.Set;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientAuthentication;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.jwt.JwtAccessTokenIssuer;
import org.picketlink.auth.oauth.jwt.JwtSettings;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;

public class JwtClientCredentialsTokenService extends ClientCredentialsTokenService {

    private final JwtAccessTokenIssuer jwtIssuer;

    public JwtClientCredentialsTokenService(ClientCredentialsAuthenticator authenticator,
            JwtAccessTokenIssuer jwtIssuer,
            JwtSettings jwtSettings) {
        this(authenticator, jwtIssuer, jwtSettings, Clock.systemUTC());
    }

    public JwtClientCredentialsTokenService(ClientCredentialsAuthenticator authenticator,
            JwtAccessTokenIssuer jwtIssuer,
            JwtSettings jwtSettings,
            Clock clock) {
        super(authenticator, new org.picketlink.auth.oauth.token.AccessTokenGenerator(),
                new org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry(), clock);
        this.jwtIssuer = jwtIssuer;
        setAccessTokenLifetimeSeconds(jwtSettings.getAccessTokenLifetimeSeconds());
    }

    @Override
    public TokenResponse issueToken(TokenRequest request) {
        validateGrantType(request.getGrantType());
        ClientAuthentication authentication = getAuthenticator().authenticate(request);
        RegisteredClient client = authentication.getClient();
        Set<String> approvedScopes = ScopeValidator.resolveApprovedScopes(client, request.getScope());
        String jwt = jwtIssuer.issueToken(client.getClientId(), approvedScopes, getServiceClock().instant());
        String scope = ScopeValidator.formatScope(approvedScopes);
        return new TokenResponse(
                jwt,
                OAuthConstants.BEARER_TOKEN_TYPE,
                getAccessTokenLifetimeSeconds(),
                scope);
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
