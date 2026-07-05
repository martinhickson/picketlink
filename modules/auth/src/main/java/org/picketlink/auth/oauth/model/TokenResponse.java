package org.picketlink.auth.oauth.model;

import org.picketlink.auth.oauth.OAuthConstants;

public final class TokenResponse {

    private final String accessToken;
    private final String tokenType;
    private final long expiresIn;
    private final String scope;

    public TokenResponse(String accessToken, long expiresIn) {
        this(accessToken, OAuthConstants.BEARER_TOKEN_TYPE, expiresIn, null);
    }

    public TokenResponse(String accessToken, String tokenType, long expiresIn, String scope) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.scope = scope;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public String getScope() {
        return scope;
    }
}
