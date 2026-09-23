package org.picketlink.auth.oauth.model;

import org.picketlink.auth.oauth.OAuthConstants;

public final class TokenResponse {

    private final String accessToken;
    private final String tokenType;
    private final long expiresIn;
    private final String scope;
    private final String refreshToken;
    private final String idToken;

    public TokenResponse(String accessToken, long expiresIn) {
        this(accessToken, OAuthConstants.BEARER_TOKEN_TYPE, expiresIn, null);
    }

    public TokenResponse(String accessToken, String tokenType, long expiresIn, String scope) {
        this(accessToken, tokenType, expiresIn, scope, null, null);
    }

    public TokenResponse(String accessToken, String tokenType, long expiresIn, String scope,
            String refreshToken, String idToken) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.scope = scope;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
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

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getIdToken() {
        return idToken;
    }
}
