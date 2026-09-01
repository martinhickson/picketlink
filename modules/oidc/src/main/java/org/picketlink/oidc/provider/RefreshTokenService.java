package org.picketlink.oidc.provider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Optional;

/**
 * Refresh tokens: opaque values stored only as SHA-256 hashes. Rotation on use per OAuth 2.1;
 * replaying a rotated token revokes the whole family (reuse detection). Persistence is
 * pluggable through {@link RefreshTokenStore} — {@link JdbcRefreshTokenStore} survives
 * restarts, the in-memory default does not.
 */
public final class RefreshTokenService {

    public static final long DEFAULT_LIFETIME_SECONDS = 14 * 24 * 3600L;

    private final RefreshTokenStore store;
    private final SecureRandom random = new SecureRandom();
    private final Clock clock;
    private final long lifetimeSeconds;

    public RefreshTokenService(Clock clock) {
        this(clock, new RefreshTokenStore.InMemoryRefreshTokenStore(), DEFAULT_LIFETIME_SECONDS);
    }

    public RefreshTokenService(Clock clock, RefreshTokenStore store) {
        this(clock, store, DEFAULT_LIFETIME_SECONDS);
    }

    public RefreshTokenService(Clock clock, RefreshTokenStore store, long lifetimeSeconds) {
        this.clock = clock;
        this.store = store;
        this.lifetimeSeconds = lifetimeSeconds;
    }

    public String create(String clientId, String subject, String scopes, String nonce) {
        String value = randomToken();
        String family = randomToken();
        store.save(new RefreshTokenRecord(hash(value), clientId, subject, scopes, nonce, family,
                clock.instant().getEpochSecond() + lifetimeSeconds));
        return value;
    }

    /**
     * Rotates the refresh token: returns the stored data plus the new token value. Replaying
     * a previously rotated token revokes the whole family (reuse detection) and fails.
     */
    public Optional<Rotation> rotate(String refreshToken) {
        if (refreshToken == null) {
            return Optional.empty();
        }
        String hash = hash(refreshToken);
        RefreshTokenRecord stored = store.find(hash);
        if (stored == null) {
            // unknown but previously seen: a rotated token is being replayed — revoke the family
            String family = store.retiredFamily(hash);
            if (family != null) {
                store.revokeFamily(family);
            }
            return Optional.empty();
        }
        if (stored.getExpiresAtEpochSeconds() <= clock.instant().getEpochSecond()) {
            store.remove(hash);
            return Optional.empty();
        }
        store.remove(hash);
        store.rememberRetired(hash, stored.getFamily());
        String newValue = randomToken();
        store.save(new RefreshTokenRecord(hash(newValue), stored.getClientId(), stored.getSubject(),
                stored.getScopes(), stored.getNonce(), stored.getFamily(),
                clock.instant().getEpochSecond() + lifetimeSeconds));
        return Optional.of(new Rotation(stored, newValue));
    }

    private String randomToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    /** Result of a successful rotation: the previous claims plus the fresh token value. */
    public static final class Rotation {

        final RefreshTokenRecord previous;
        final String newRefreshToken;

        Rotation(RefreshTokenRecord previous, String newRefreshToken) {
            this.previous = previous;
            this.newRefreshToken = newRefreshToken;
        }

        public String getClientId() {
            return previous.getClientId();
        }

        public String getSubject() {
            return previous.getSubject();
        }

        public String getScopes() {
            return previous.getScopes();
        }

        public String getNewRefreshToken() {
            return newRefreshToken;
        }
    }
}
