package org.picketlink.auth.oauth;

import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ClientRegistry;
import org.picketlink.auth.oauth.client.ClientSecretMatcher;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.InMemoryClientRegistry;
import org.picketlink.auth.oauth.client.store.ClientRegistrationStore;
import org.picketlink.auth.oauth.client.store.PersistingClientRegistry;
import org.picketlink.auth.oauth.metadata.OAuthAuthorizationServerMetadata;
import org.picketlink.auth.oauth.service.ClientCredentialsTokenService;
import org.picketlink.auth.oauth.token.AccessTokenGenerator;
import org.picketlink.auth.oauth.token.AccessTokenRegistry;
import org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry;

public final class ClientCredentialsAuthServer {

    private final ClientRegistry clientRegistry;
    private final AccessTokenRegistry accessTokenRegistry;
    private final ClientCredentialsTokenService tokenService;
    private final OAuthAuthorizationServerMetadata metadata;

    private ClientCredentialsAuthServer(Builder builder) {
        this.clientRegistry = builder.clientRegistry;
        this.accessTokenRegistry = builder.accessTokenRegistry;
        ClientSecretMatcher secretMatcher = builder.secretMatcher;
        ClientCredentialsAuthenticator authenticator =
                new ClientCredentialsAuthenticator(clientRegistry, secretMatcher);
        AccessTokenGenerator tokenGenerator = new AccessTokenGenerator();
        this.tokenService = new ClientCredentialsTokenService(
                authenticator,
                tokenGenerator,
                accessTokenRegistry,
                builder.clock == null ? java.time.Clock.systemUTC() : builder.clock);
        if (builder.accessTokenLifetimeSeconds > 0) {
            this.tokenService.setAccessTokenLifetimeSeconds(builder.accessTokenLifetimeSeconds);
        }
        this.metadata = new OAuthAuthorizationServerMetadata(
                builder.issuer,
                builder.tokenEndpoint,
                builder.scopesSupported);
    }

    public ClientRegistry getClientRegistry() {
        return clientRegistry;
    }

    public AccessTokenRegistry getAccessTokenRegistry() {
        return accessTokenRegistry;
    }

    public ClientCredentialsTokenService getTokenService() {
        return tokenService;
    }

    public OAuthAuthorizationServerMetadata getMetadata() {
        return metadata;
    }

    public static Builder builder(String issuer, String tokenEndpoint) {
        return new Builder(issuer, tokenEndpoint);
    }

    public static final class Builder {
        private final String issuer;
        private final String tokenEndpoint;
        private ClientRegistry clientRegistry = new InMemoryClientRegistry();
        private AccessTokenRegistry accessTokenRegistry = new InMemoryAccessTokenRegistry();
        private ClientSecretMatcher secretMatcher = new ConstantTimeClientSecretMatcher();
        private java.time.Clock clock;
        private long accessTokenLifetimeSeconds = 3600L;
        private java.util.List<String> scopesSupported = java.util.Collections.emptyList();

        private Builder(String issuer, String tokenEndpoint) {
            this.issuer = issuer;
            this.tokenEndpoint = tokenEndpoint;
        }

        public Builder clientRegistry(ClientRegistry clientRegistry) {
            this.clientRegistry = clientRegistry;
            return this;
        }

        public Builder accessTokenRegistry(AccessTokenRegistry accessTokenRegistry) {
            this.accessTokenRegistry = accessTokenRegistry;
            return this;
        }

        public Builder secretMatcher(ClientSecretMatcher secretMatcher) {
            this.secretMatcher = secretMatcher;
            return this;
        }

        public Builder clock(java.time.Clock clock) {
            this.clock = clock;
            return this;
        }

        public Builder accessTokenLifetimeSeconds(long accessTokenLifetimeSeconds) {
            this.accessTokenLifetimeSeconds = accessTokenLifetimeSeconds;
            return this;
        }

        public Builder scopesSupported(java.util.List<String> scopesSupported) {
            this.scopesSupported = scopesSupported;
            return this;
        }

        public Builder clientRegistrationStore(ClientRegistrationStore store) {
            return clientRegistry(new PersistingClientRegistry(store));
        }

        public ClientCredentialsAuthServer build() {
            return new ClientCredentialsAuthServer(this);
        }
    }
}
