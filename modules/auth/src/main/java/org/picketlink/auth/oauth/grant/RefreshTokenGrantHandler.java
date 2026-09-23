package org.picketlink.auth.oauth.grant;

import java.time.Clock;
import java.util.Set;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientAuthentication;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.service.ScopeValidator;
import org.picketlink.auth.oauth.token.RefreshTokenStore;
import org.picketlink.auth.oauth.token.RefreshTokenStore.IssuedRefreshToken;

public final class RefreshTokenGrantHandler implements GrantHandler {

    private final ClientCredentialsAuthenticator clientAuthenticator;
    private final SubjectAccessTokenIssuer accessTokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final long accessTokenLifetimeSeconds;
    private final Clock clock;

    public RefreshTokenGrantHandler(ClientCredentialsAuthenticator clientAuthenticator,
            SubjectAccessTokenIssuer accessTokenIssuer,
            RefreshTokenStore refreshTokenStore,
            long accessTokenLifetimeSeconds,
            Clock clock) {
        this.clientAuthenticator = clientAuthenticator;
        this.accessTokenIssuer = accessTokenIssuer;
        this.refreshTokenStore = refreshTokenStore;
        this.accessTokenLifetimeSeconds = accessTokenLifetimeSeconds;
        this.clock = clock;
    }

    @Override
    public String grantType() {
        return OAuthConstants.REFRESH_TOKEN_GRANT;
    }

    @Override
    public TokenResponse issue(TokenRequest request) {
        String presented = request.getFormParameter(OAuthConstants.REFRESH_TOKEN);
        if (presented == null || presented.isBlank()) {
            throw new OAuthException(
                    new OAuthErrorResponse(OAuthConstants.INVALID_REQUEST, "refresh_token is required"),
                    400);
        }
        ClientAuthentication authentication = clientAuthenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();
        IssuedRefreshToken rotated = refreshTokenStore.rotate(presented, client.getClientId());
        Set<String> scopes = rotated.getScopes();
        String accessToken = accessTokenIssuer.issue(rotated.getSubject(), client.getClientId(), scopes,
                clock.instant());
        return new TokenResponse(accessToken, OAuthConstants.BEARER_TOKEN_TYPE, accessTokenLifetimeSeconds,
                ScopeValidator.formatScope(scopes), rotated.getToken(), null);
    }
}
