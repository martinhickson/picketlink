package org.picketlink.oidc;

import java.util.ArrayList;
import java.util.List;

/**
 * One OAuth client registered with the authorization server: id, secret, redirects, scopes, grants.
 */
public final class OidcClientRegistration {

    private final String clientId;
    private final String clientSecret;
    private final List<String> redirectUris;
    private final List<String> scopes;
    private final List<String> grantTypes;
    private final String applicationName;

    public OidcClientRegistration(String clientId, String clientSecret, List<String> redirectUris,
            List<String> scopes, List<String> grantTypes, String applicationName) {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("clientId is required");
        }
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalArgumentException("clientSecret is required");
        }
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw new IllegalArgumentException("at least one redirect URI is required");
        }
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUris = List.copyOf(redirectUris);
        this.scopes = scopes == null || scopes.isEmpty()
                ? List.of(OidcDemoConstants.OPENID_SCOPE)
                : List.copyOf(scopes);
        this.grantTypes = grantTypes == null || grantTypes.isEmpty()
                ? List.of("authorization_code", "refresh_token")
                : List.copyOf(grantTypes);
        this.applicationName = applicationName == null || applicationName.isBlank()
                ? clientId
                : applicationName;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public String getApplicationName() {
        return applicationName;
    }

    /** Web URI derived from the first redirect, matching the demo RP layout when it contains {@code /oidc/}. */
    public String applicationWebUri() {
        String redirect = redirectUris.get(0);
        int marker = redirect.lastIndexOf("/oidc/");
        if (marker < 0) {
            return redirect;
        }
        return redirect.substring(0, marker + 1);
    }

    public static Builder builder(String clientId, String clientSecret) {
        return new Builder(clientId, clientSecret);
    }

    public static final class Builder {
        private final String clientId;
        private final String clientSecret;
        private final List<String> redirectUris = new ArrayList<>();
        private final List<String> scopes = new ArrayList<>();
        private final List<String> grantTypes = new ArrayList<>();
        private String applicationName;

        private Builder(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        public Builder redirectUri(String redirectUri) {
            redirectUris.add(redirectUri);
            return this;
        }

        public Builder scope(String scope) {
            scopes.add(scope);
            return this;
        }

        public Builder grantType(String grantType) {
            grantTypes.add(grantType);
            return this;
        }

        public Builder applicationName(String applicationName) {
            this.applicationName = applicationName;
            return this;
        }

        public OidcClientRegistration build() {
            return new OidcClientRegistration(clientId, clientSecret, redirectUris, scopes, grantTypes,
                    applicationName);
        }
    }
}
