package org.picketlink.auth.oauth.model;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

public final class AccessTokenRecord {

    private final String tokenValue;
    private final String clientId;
    private final Set<String> scopes;
    private final Instant issuedAt;
    private final Instant expiresAt;

    public AccessTokenRecord(String tokenValue, String clientId, Set<String> scopes,
            Instant issuedAt, Instant expiresAt) {
        this.tokenValue = Objects.requireNonNull(tokenValue, "tokenValue");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public String getClientId() {
        return clientId;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }
}
