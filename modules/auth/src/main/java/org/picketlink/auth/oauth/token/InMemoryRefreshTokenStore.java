package org.picketlink.auth.oauth.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;

public final class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private final Clock clock;
    private final AccessTokenGenerator generator;
    private final Map<String, Record> tokens = new ConcurrentHashMap<>();

    public InMemoryRefreshTokenStore() {
        this(Clock.systemUTC());
    }

    public InMemoryRefreshTokenStore(Clock clock) {
        this.clock = clock;
        this.generator = new AccessTokenGenerator();
    }

    @Override
    public IssuedRefreshToken issue(String subject, String clientId, Set<String> scopes, Duration lifetime) {
        if (lifetime == null || lifetime.isZero() || lifetime.isNegative()) {
            throw new IllegalArgumentException("refresh token lifetime must be positive");
        }
        String token = generator.generate();
        Instant expiresAt = clock.instant().plus(lifetime);
        tokens.put(token, new Record(subject, clientId, Set.copyOf(scopes), expiresAt, lifetime));
        return new IssuedRefreshToken(token, subject, clientId, scopes, expiresAt);
    }

    @Override
    public IssuedRefreshToken rotate(String presentedToken, String clientId) {
        Record record = tokens.get(presentedToken);
        if (record == null || !record.clientId.equals(clientId) || !record.expiresAt.isAfter(clock.instant())) {
            if (record != null && record.clientId.equals(clientId)) {
                tokens.remove(presentedToken);
            }
            throw new OAuthException(
                    new OAuthErrorResponse(OAuthConstants.INVALID_GRANT, "refresh_token is invalid"),
                    400);
        }
        tokens.remove(presentedToken);
        return issue(record.subject, record.clientId, record.scopes, record.lifetime);
    }

    private static final class Record {
        private final String subject;
        private final String clientId;
        private final Set<String> scopes;
        private final Instant expiresAt;
        private final Duration lifetime;

        private Record(String subject, String clientId, Set<String> scopes, Instant expiresAt, Duration lifetime) {
            this.subject = subject;
            this.clientId = clientId;
            this.scopes = scopes;
            this.expiresAt = expiresAt;
            this.lifetime = lifetime;
        }
    }
}
