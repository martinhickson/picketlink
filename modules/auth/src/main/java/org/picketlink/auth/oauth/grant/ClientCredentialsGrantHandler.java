package org.picketlink.auth.oauth.grant;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.service.ClientCredentialsTokenService;

public final class ClientCredentialsGrantHandler implements GrantHandler {

    private final ClientCredentialsTokenService tokenService;

    public ClientCredentialsGrantHandler(ClientCredentialsTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public String grantType() {
        return OAuthConstants.CLIENT_CREDENTIALS_GRANT;
    }

    @Override
    public TokenResponse issue(TokenRequest request) {
        return tokenService.issueToken(request);
    }
}
