package org.picketlink.auth.oauth.service;

import java.time.Clock;
import java.util.Set;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientAuthentication;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.issuance.IssuanceRequest;
import org.picketlink.auth.oauth.issuance.IssuedToken;
import org.picketlink.auth.oauth.issuance.JwtIssuanceManager;
import org.picketlink.auth.oauth.jwt.JwtAccessTokenIssuer;
import org.picketlink.auth.oauth.jwt.JwtSettings;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;

/**
 * Issues JWT access tokens through the {@link JwtIssuanceManager} chokepoint so every token is
 * policy-checked, registered and audited. The legacy constructor (direct
 * {@link JwtAccessTokenIssuer}) is retained for existing deployments but bypasses those controls.
 */
public class JwtClientCredentialsTokenService extends ClientCredentialsTokenService {

    private final JwtAccessTokenIssuer legacyIssuer;
    private final JwtIssuanceManager issuanceManager;
    private final Set<String> audiences;

    /**
     * @deprecated use {@link #JwtClientCredentialsTokenService(ClientCredentialsAuthenticator, JwtIssuanceManager, Set)}
     */
    @Deprecated
    public JwtClientCredentialsTokenService(ClientCredentialsAuthenticator authenticator,
            JwtAccessTokenIssuer jwtIssuer,
            JwtSettings jwtSettings) {
        this(authenticator, jwtIssuer, jwtSettings, Clock.systemUTC());
    }

    /**
     * @deprecated use {@link #JwtClientCredentialsTokenService(ClientCredentialsAuthenticator, JwtIssuanceManager, Set)}
     */
    @Deprecated
    public JwtClientCredentialsTokenService(ClientCredentialsAuthenticator authenticator,
            JwtAccessTokenIssuer jwtIssuer,
            JwtSettings jwtSettings,
            Clock clock) {
        super(authenticator, new org.picketlink.auth.oauth.token.AccessTokenGenerator(),
                new org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry(), clock);
        this.legacyIssuer = jwtIssuer;
        this.issuanceManager = null;
        setAccessTokenLifetimeSeconds(jwtSettings.getAccessTokenLifetimeSeconds());
        this.audiences = Set.of();
    }

    public JwtClientCredentialsTokenService(ClientCredentialsAuthenticator authenticator,
            JwtIssuanceManager issuanceManager) {
        this(authenticator, issuanceManager, Set.of(), Clock.systemUTC());
    }

    public JwtClientCredentialsTokenService(ClientCredentialsAuthenticator authenticator,
            JwtIssuanceManager issuanceManager, Set<String> audiences, Clock clock) {
        super(authenticator, new org.picketlink.auth.oauth.token.AccessTokenGenerator(),
                new org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry(), clock);
        this.legacyIssuer = null;
        this.issuanceManager = issuanceManager;
        this.audiences = Set.copyOf(audiences);
    }

    @Override
    public TokenResponse issueToken(TokenRequest request) {
        validateGrantType(request.getGrantType());
        ClientAuthentication authentication = getAuthenticator().authenticate(request);
        RegisteredClient client = authentication.getClient();
        Set<String> approvedScopes = ScopeValidator.resolveApprovedScopes(client, request.getScope());

        IssuedToken issued;
        if (issuanceManager != null) {
            issued = issuanceManager.issue(IssuanceRequest.forClient(client)
                    .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                    .scopes(approvedScopes)
                    .audiences(audiences)
                    .build());
        } else {
            String jwt = legacyIssuer.issueToken(client.getClientId(), approvedScopes, getServiceClock().instant());
            issued = new IssuedToken(jwt, null, getAccessTokenLifetimeSeconds(), approvedScopes);
        }
        String scope = ScopeValidator.formatScope(approvedScopes);
        return new TokenResponse(
                issued.getTokenValue(),
                OAuthConstants.BEARER_TOKEN_TYPE,
                issued.getLifetimeSeconds(),
                scope);
    }

    /** Exposed so endpoint layers can validate/audit bearer tokens through the same manager. */
    public JwtClaims validateToken(String tokenValue) {
        if (issuanceManager == null) {
            throw new IllegalStateException("Token validation requires the managed constructor");
        }
        return issuanceManager.validate(tokenValue);
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
