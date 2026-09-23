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
     * Revokes this refresh token and the rest of its family when it belongs to {@code clientId}.
     * A token issued to another client is left in place.
     */
    public void revoke(String refreshToken, String clientId) {
        if (refreshToken == null || clientId == null) {
            return;
        }
        String hash = hash(refreshToken);
        RefreshTokenRecord stored = store.remove(hash);
        if (stored == null) {
            String family = store.retiredFamily(hash);
            if (family != null) {
                store.revokeFamily(family);
            }
            return;
        }
        if (!clientId.equals(stored.getClientId())) {
            store.save(stored);
            return;
        }
        store.revokeFamily(stored.getFamily());
    }

    /** The live record for this token. Does not rotate, retire, or revoke. */
    public Optional<RefreshTokenRecord> findLive(String refreshToken) {
        if (refreshToken == null) {
            return Optional.empty();
        }
        RefreshTokenRecord stored = store.find(hash(refreshToken));
        if (stored == null) {
            return Optional.empty();
        }
        return Optional.of(stored);
    }

    /**
     * Rotates the refresh token: returns the stored data plus the new token value. Replaying
     * a previously rotated token revokes the whole family (reuse detection) and fails.
     */
    public Optional<Rotation> rotate(String refreshToken) {
        return rotate(refreshToken, null, null);
    }

    /**
     * @param expectedClientId when set, a token issued to another client is left untouched
     * @param scopes when set, the rotated token carries these scopes instead of the previous ones
     */
    public Optional<Rotation> rotate(String refreshToken, String expectedClientId, String scopes) {
        if (refreshToken == null) {
            return Optional.empty();
        }
        String hash = hash(refreshToken);
        RefreshTokenRecord stored = store.remove(hash);
        if (stored == null) {
            // unknown but previously seen: a rotated token is being replayed — revoke the family
            String family = store.retiredFamily(hash);
            if (family != null) {
                store.revokeFamily(family);
            }
            return Optional.empty();
        }
        if (stored.getExpiresAtEpochSeconds() <= clock.instant().getEpochSecond()) {
            return Optional.empty();
        }
        if (expectedClientId != null && !expectedClientId.equals(stored.getClientId())) {
            store.save(stored);
            return Optional.empty();
        }
        store.rememberRetired(hash, stored.getFamily());
        String newValue = randomToken();
        String nextScopes = scopes != null ? scopes : stored.getScopes();
        store.save(new RefreshTokenRecord(hash(newValue), stored.getClientId(), stored.getSubject(),
                nextScopes, stored.getNonce(), stored.getFamily(),
                clock.instant().getEpochSecond() + lifetimeSeconds));
        return Optional.of(new Rotation(stored, newValue, nextScopes));
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
        final String scopes;

        Rotation(RefreshTokenRecord previous, String newRefreshToken, String scopes) {
            this.previous = previous;
            this.newRefreshToken = newRefreshToken;
            this.scopes = scopes;
        }

        public String getClientId() {
            return previous.getClientId();
        }

        public String getSubject() {
            return previous.getSubject();
        }

        public String getScopes() {
            return scopes;
        }

        public String getNewRefreshToken() {
            return newRefreshToken;
        }
    }
}
