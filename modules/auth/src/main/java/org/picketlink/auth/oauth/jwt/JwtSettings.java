package org.picketlink.auth.oauth.jwt;

public final class JwtSettings {

    private final String issuer;
    private final String signingSecret;
    private final long accessTokenLifetimeSeconds;

    public JwtSettings(String issuer, String signingSecret, long accessTokenLifetimeSeconds) {
        this.issuer = issuer;
        this.signingSecret = signingSecret;
        this.accessTokenLifetimeSeconds = accessTokenLifetimeSeconds;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSigningSecret() {
        return signingSecret;
    }

    public long getAccessTokenLifetimeSeconds() {
        return accessTokenLifetimeSeconds;
    }
}
