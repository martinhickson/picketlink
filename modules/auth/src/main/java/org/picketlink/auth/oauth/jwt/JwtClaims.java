package org.picketlink.auth.oauth.jwt;

public final class JwtClaims {

    private final String clientId;
    private final String scope;

    public JwtClaims(String clientId, String scope) {
        this.clientId = clientId;
        this.scope = scope;
    }

    public String getClientId() {
        return clientId;
    }

    public String getScope() {
        return scope;
    }
}
