package org.picketlink.auth.oauth.service;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientAuthentication;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.issuance.JwtIssuanceManager;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.TokenRequest;

/**
 * RFC 7009 token revocation. Per the RFC, the response is always 200 (with an empty body) for
 * authenticated clients, even when the token is unknown; only authentication failures yield 401.
 */
public class TokenRevocationService {

    private final ClientCredentialsAuthenticator authenticator;
    private final JwtIssuanceManager issuanceManager;

    public TokenRevocationService(ClientCredentialsAuthenticator authenticator,
            JwtIssuanceManager issuanceManager) {
        this.authenticator = authenticator;
        this.issuanceManager = issuanceManager;
    }

    public void revoke(TokenRequest request) {
        ClientAuthentication authentication = authenticator.authenticate(request);
        String token = request.getFormParameter(OAuthConstants.ACCESS_TOKEN);
        if (token == null || token.isBlank()) {
            throw new OAuthException(
                    new OAuthErrorResponse(OAuthConstants.INVALID_REQUEST, "token is required"), 400);
        }
        issuanceManager.revoke(token, authentication.getClient().getClientId());
    }
}
