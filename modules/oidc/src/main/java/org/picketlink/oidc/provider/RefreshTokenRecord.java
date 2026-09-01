package org.picketlink.oidc.provider;

/**
 * Persisted refresh token state. Keyed by the SHA-256 hash of the token value — the raw
 * token exists only in the client's hands.
 */
public final class RefreshTokenRecord {

    private final String tokenHash;
    private final String clientId;
    private final String subject;
    private final String scopes;
    private final String nonce;
    private final String family;
    private final long expiresAtEpochSeconds;

    public RefreshTokenRecord(String tokenHash, String clientId, String subject, String scopes,
            String nonce, String family, long expiresAtEpochSeconds) {
        this.tokenHash = tokenHash;
        this.clientId = clientId;
        this.subject = subject;
        this.scopes = scopes;
        this.nonce = nonce;
        this.family = family;
        this.expiresAtEpochSeconds = expiresAtEpochSeconds;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSubject() {
        return subject;
    }

    public String getScopes() {
        return scopes;
    }

    public String getNonce() {
        return nonce;
    }

    public String getFamily() {
        return family;
    }

    public long getExpiresAtEpochSeconds() {
        return expiresAtEpochSeconds;
    }
}
