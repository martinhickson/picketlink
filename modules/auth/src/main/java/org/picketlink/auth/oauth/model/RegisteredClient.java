package org.picketlink.auth.oauth.model;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

public final class RegisteredClient {

    private final String clientId;
    private final String clientSecret;
    private final Set<String> scopes;
    private final TokenEndpointAuthMethod tokenEndpointAuthMethod;
    private final Set<String> allowedAudiences;
    private final Set<String> allowedRedirectUris;
    private final String jwks;
    private final String backchannelLogoutUrl;
    private final long maxTokenLifetimeSeconds;

    private RegisteredClient(Builder builder) {
        this.clientId = Objects.requireNonNull(builder.clientId, "clientId");
        this.clientSecret = builder.clientSecret;
        this.scopes = Collections.unmodifiableSet(new LinkedHashSet<>(builder.scopes));
        this.tokenEndpointAuthMethod = builder.tokenEndpointAuthMethod;
        this.allowedAudiences = Collections.unmodifiableSet(new LinkedHashSet<>(builder.allowedAudiences));
        this.allowedRedirectUris = Collections.unmodifiableSet(new LinkedHashSet<>(builder.allowedRedirectUris));
        this.jwks = builder.jwks;
        this.backchannelLogoutUrl = builder.backchannelLogoutUrl;
        this.maxTokenLifetimeSeconds = builder.maxTokenLifetimeSeconds;
    }

    public String getClientId() {
        return clientId;
    }

    /**
     * May be null for clients that do not authenticate with a static secret
     * (e.g. {@link TokenEndpointAuthMethod#PRIVATE_KEY_JWT}).
     */
    public String getClientSecret() {
        return clientSecret;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public TokenEndpointAuthMethod getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    /** Audience allow-list; empty means "no pinning". */
    public Set<String> getAllowedAudiences() {
        return allowedAudiences;
    }

    /** Registered redirect URIs for the OIDC authorization code flow. */
    public Set<String> getAllowedRedirectUris() {
        return allowedRedirectUris;
    }

    /** JWKS document with the client's public keys, used to verify client assertions. */
    public String getJwks() {
        return jwks;
    }

    /** OIDC Back-Channel Logout 1.0 callback URL; null when the client does not support it. */
    public String getBackchannelLogoutUrl() {
        return backchannelLogoutUrl;
    }

    /** Per-client token lifetime cap; zero means "use the server default/maximum". */
    public long getMaxTokenLifetimeSeconds() {
        return maxTokenLifetimeSeconds;
    }

    public static Builder builder(String clientId, String clientSecret) {
        return new Builder(clientId, clientSecret);
    }

    public static final class Builder {
        private final String clientId;
        private final String clientSecret;
        private final Set<String> scopes = new LinkedHashSet<>();
        private TokenEndpointAuthMethod tokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC;
        private final Set<String> allowedAudiences = new LinkedHashSet<>();
        private final Set<String> allowedRedirectUris = new LinkedHashSet<>();
        private String jwks;
        private String backchannelLogoutUrl;
        private long maxTokenLifetimeSeconds;

        private Builder(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        public Builder scope(String scope) {
            scopes.add(scope);
            return this;
        }

        public Builder scopes(Set<String> values) {
            scopes.addAll(values);
            return this;
        }

        public Builder tokenEndpointAuthMethod(TokenEndpointAuthMethod method) {
            this.tokenEndpointAuthMethod = method;
            return this;
        }

        public Builder allowedAudience(String audience) {
            allowedAudiences.add(audience);
            return this;
        }

        public Builder allowedAudiences(Set<String> values) {
            allowedAudiences.addAll(values);
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            allowedRedirectUris.add(redirectUri);
            return this;
        }

        public Builder allowedRedirectUris(Set<String> values) {
            allowedRedirectUris.addAll(values);
            return this;
        }

        public Builder jwks(String jwks) {
            this.jwks = jwks;
            return this;
        }

        public Builder backchannelLogoutUrl(String url) {
            this.backchannelLogoutUrl = url;
            return this;
        }

        public Builder maxTokenLifetimeSeconds(long maxTokenLifetimeSeconds) {
            this.maxTokenLifetimeSeconds = maxTokenLifetimeSeconds;
            return this;
        }

        public RegisteredClient build() {
            if (tokenEndpointAuthMethod != TokenEndpointAuthMethod.PRIVATE_KEY_JWT
                    && clientSecret == null) {
                throw new IllegalArgumentException(
                        "clientSecret is required unless the client authenticates with private_key_jwt");
            }
            if (tokenEndpointAuthMethod == TokenEndpointAuthMethod.PRIVATE_KEY_JWT
                    && (jwks == null || jwks.isBlank())) {
                throw new IllegalArgumentException(
                        "A JWKS document is required for private_key_jwt clients");
            }
            return new RegisteredClient(this);
        }
    }
}
