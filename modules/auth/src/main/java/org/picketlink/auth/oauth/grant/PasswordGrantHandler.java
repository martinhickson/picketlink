package org.picketlink.auth.oauth.grant;

import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientAuthentication;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.grant.ResourceOwnerAuthenticator.ResourceOwner;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.service.ScopeValidator;
import org.picketlink.auth.oauth.token.RefreshTokenStore;
import org.picketlink.auth.oauth.token.RefreshTokenStore.IssuedRefreshToken;

public final class PasswordGrantHandler implements GrantHandler {

    private final ClientCredentialsAuthenticator clientAuthenticator;
    private final ResourceOwnerAuthenticator resourceOwnerAuthenticator;
    private final SubjectAccessTokenIssuer accessTokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final Duration refreshLifetime;
    private final long accessTokenLifetimeSeconds;
    private final Clock clock;

    public PasswordGrantHandler(ClientCredentialsAuthenticator clientAuthenticator,
            ResourceOwnerAuthenticator resourceOwnerAuthenticator,
            SubjectAccessTokenIssuer accessTokenIssuer,
            RefreshTokenStore refreshTokenStore,
            Duration refreshLifetime,
            long accessTokenLifetimeSeconds,
            Clock clock) {
        this.clientAuthenticator = clientAuthenticator;
        this.resourceOwnerAuthenticator = resourceOwnerAuthenticator;
        this.accessTokenIssuer = accessTokenIssuer;
        this.refreshTokenStore = refreshTokenStore;
        this.refreshLifetime = refreshLifetime;
        this.accessTokenLifetimeSeconds = accessTokenLifetimeSeconds;
        this.clock = clock;
    }

    @Override
    public String grantType() {
        return OAuthConstants.PASSWORD_GRANT;
    }

    @Override
    public TokenResponse issue(TokenRequest request) {
        String username = request.getFormParameter(OAuthConstants.USERNAME);
        String password = request.getFormParameter(OAuthConstants.PASSWORD);
        if (username == null || username.isBlank() || password == null) {
            throw new OAuthException(
                    new OAuthErrorResponse(OAuthConstants.INVALID_REQUEST, "username and password are required"),
                    400);
        }
        ClientAuthentication authentication = clientAuthenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();
        ResourceOwner owner = resourceOwnerAuthenticator.authenticate(username, password);
        Set<String> approved = ScopeValidator.resolveApprovedScopes(client, request.getScope());
        String accessToken = accessTokenIssuer.issue(owner.getSubject(), client.getClientId(), approved,
                clock.instant());
        IssuedRefreshToken refresh = refreshTokenStore.issue(owner.getSubject(), client.getClientId(), approved,
                refreshLifetime);
        return new TokenResponse(accessToken, OAuthConstants.BEARER_TOKEN_TYPE, accessTokenLifetimeSeconds,
                ScopeValidator.formatScope(approved), refresh.getToken(), null);
    }
}
