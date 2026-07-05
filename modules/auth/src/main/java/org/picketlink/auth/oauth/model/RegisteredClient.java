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

    private RegisteredClient(Builder builder) {
        this.clientId = Objects.requireNonNull(builder.clientId, "clientId");
        this.clientSecret = Objects.requireNonNull(builder.clientSecret, "clientSecret");
        this.scopes = Collections.unmodifiableSet(new LinkedHashSet<>(builder.scopes));
        this.tokenEndpointAuthMethod = builder.tokenEndpointAuthMethod;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public TokenEndpointAuthMethod getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public static Builder builder(String clientId, String clientSecret) {
        return new Builder(clientId, clientSecret);
    }

    public static final class Builder {
        private final String clientId;
        private final String clientSecret;
        private final Set<String> scopes = new LinkedHashSet<>();
        private TokenEndpointAuthMethod tokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC;

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

        public RegisteredClient build() {
            return new RegisteredClient(this);
        }
    }
}
