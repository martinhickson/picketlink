package org.picketlink.oidc;

import java.util.ArrayList;
import java.util.List;

/**
 * Authorization server settings. Issuer, clients, users, and the keystore are supplied by the
 * caller. The demo WAR is one such caller.
 */
public final class OidcAuthorizationServerConfig {

    private final String issuer;
    private final List<OidcClientRegistration> clients;
    private final List<OidcUserRegistration> users;
    private final OidcKeystoreConfig keystore;

    private OidcAuthorizationServerConfig(Builder builder) {
        if (builder.issuer == null || builder.issuer.isBlank()) {
            throw new IllegalArgumentException("issuer is required");
        }
        if (builder.clients.isEmpty()) {
            throw new IllegalArgumentException("at least one client is required");
        }
        this.issuer = trimTrailingSlash(builder.issuer);
        this.clients = List.copyOf(builder.clients);
        this.users = List.copyOf(builder.users);
        this.keystore = builder.keystore;
    }

    public String getIssuer() {
        return issuer;
    }

    public List<OidcClientRegistration> getClients() {
        return clients;
    }

    public List<OidcUserRegistration> getUsers() {
        return users;
    }

    public OidcKeystoreConfig getKeystore() {
        return keystore;
    }

    public List<String> scopes() {
        List<String> scopes = new ArrayList<>();
        for (OidcClientRegistration client : clients) {
            for (String scope : client.getScopes()) {
                if (!scopes.contains(scope)) {
                    scopes.add(scope);
                }
            }
        }
        return scopes;
    }

    public static Builder builder(String issuer) {
        return new Builder(issuer);
    }

    private static String trimTrailingSlash(String url) {
        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }

    public static final class Builder {
        private final String issuer;
        private final List<OidcClientRegistration> clients = new ArrayList<>();
        private final List<OidcUserRegistration> users = new ArrayList<>();
        private OidcKeystoreConfig keystore;

        private Builder(String issuer) {
            this.issuer = issuer;
        }

        public Builder client(OidcClientRegistration client) {
            clients.add(client);
            return this;
        }

        public Builder user(OidcUserRegistration user) {
            users.add(user);
            return this;
        }

        public Builder keystore(OidcKeystoreConfig keystore) {
            this.keystore = keystore;
            return this;
        }

        public OidcAuthorizationServerConfig build() {
            return new OidcAuthorizationServerConfig(this);
        }
    }
}
