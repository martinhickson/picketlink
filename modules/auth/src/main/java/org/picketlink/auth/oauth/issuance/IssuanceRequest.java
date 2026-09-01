package org.picketlink.auth.oauth.issuance;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.picketlink.auth.oauth.model.RegisteredClient;

/** Input to {@link JwtIssuanceManager#issue(IssuanceRequest)}. */
public final class IssuanceRequest {

    private final RegisteredClient client;
    private final String grantType;
    private final Set<String> scopes;
    private final Set<String> audiences;
    private final Long requestedLifetimeSeconds;
    private final String subject;
    private final String nonce;
    private final Map<String, String> extraClaims;

    private IssuanceRequest(Builder builder) {
        this.client = builder.client;
        this.grantType = builder.grantType;
        this.scopes = new LinkedHashSet<>(builder.scopes);
        this.audiences = new LinkedHashSet<>(builder.audiences);
        this.requestedLifetimeSeconds = builder.requestedLifetimeSeconds;
        this.subject = builder.subject;
        this.nonce = builder.nonce;
        this.extraClaims = new LinkedHashMap<>(builder.extraClaims);
    }

    public RegisteredClient getClient() {
        return client;
    }

    public String getGrantType() {
        return grantType;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public Set<String> getAudiences() {
        return audiences;
    }

    /** Nullable: falls back to the manager default before policy rules clamp it. */
    public Long getRequestedLifetimeSeconds() {
        return requestedLifetimeSeconds;
    }

    /** Token subject; null means the client id (client_credentials semantics). */
    public String getSubject() {
        return subject;
    }

    /** OIDC nonce to embed in ID tokens; nullable. */
    public String getNonce() {
        return nonce;
    }

    /** Additional claims (e.g. OIDC profile claims) merged into the token. */
    public Map<String, String> getExtraClaims() {
        return extraClaims;
    }

    public static Builder forClient(RegisteredClient client) {
        return new Builder(client);
    }

    public static final class Builder {
        private final RegisteredClient client;
        private String grantType;
        private final Set<String> scopes = new LinkedHashSet<>();
        private final Set<String> audiences = new LinkedHashSet<>();
        private Long requestedLifetimeSeconds;
        private String subject;
        private String nonce;
        private final Map<String, String> extraClaims = new LinkedHashMap<>();

        private Builder(RegisteredClient client) {
            this.client = client;
        }

        public Builder grantType(String grantType) {
            this.grantType = grantType;
            return this;
        }

        public Builder scopes(Set<String> values) {
            if (values != null) {
                scopes.addAll(values);
            }
            return this;
        }

        public Builder audiences(Set<String> values) {
            if (values != null) {
                audiences.addAll(values);
            }
            return this;
        }

        public Builder requestedLifetimeSeconds(Long lifetimeSeconds) {
            this.requestedLifetimeSeconds = lifetimeSeconds;
            return this;
        }

        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder extraClaims(Map<String, String> claims) {
            if (claims != null) {
                extraClaims.putAll(claims);
            }
            return this;
        }

        public IssuanceRequest build() {
            return new IssuanceRequest(this);
        }
    }
}
