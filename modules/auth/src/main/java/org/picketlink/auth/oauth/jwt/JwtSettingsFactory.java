package org.picketlink.auth.oauth.jwt;

public final class JwtSettingsFactory {

    public static final String JWT_SECRET_PROPERTY = "picketlink.auth.jwt.secret";
    public static final String JWT_ISSUER_PROPERTY = "picketlink.auth.jwt.issuer";
    public static final String AUTH_BASE_URL_PROPERTY = "picketlink.auth.base.url";
    public static final String JWT_LIFETIME_PROPERTY = "picketlink.auth.jwt.lifetime.seconds";

    private JwtSettingsFactory() {
    }

    public static JwtSettings fromEnvironment() {
        int port = Integer.getInteger("test.http.port", 8080);
        String baseUrl = System.getProperty(AUTH_BASE_URL_PROPERTY, "http://localhost:" + port + "/auth");
        String issuer = System.getProperty(JWT_ISSUER_PROPERTY, baseUrl);
        String secret = System.getProperty(JWT_SECRET_PROPERTY, "picketlink-auth-it-secret");
        long lifetime = Long.getLong(JWT_LIFETIME_PROPERTY, 3600L);
        return new JwtSettings(issuer, secret, lifetime);
    }
}
