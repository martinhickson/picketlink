package org.picketlink.auth.oauth.token;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

public interface RefreshTokenStore {

    IssuedRefreshToken issue(String subject, String clientId, Set<String> scopes, Duration lifetime);

    IssuedRefreshToken rotate(String presentedToken, String clientId);

    final class IssuedRefreshToken {
        private final String token;
        private final String subject;
        private final String clientId;
        private final Set<String> scopes;
        private final Instant expiresAt;

        public IssuedRefreshToken(String token, String subject, String clientId, Set<String> scopes,
                Instant expiresAt) {
            this.token = token;
            this.subject = subject;
            this.clientId = clientId;
            this.scopes = Set.copyOf(scopes);
            this.expiresAt = expiresAt;
        }

        public String getToken() {
            return token;
        }

        public String getSubject() {
            return subject;
        }

        public String getClientId() {
            return clientId;
        }

        public Set<String> getScopes() {
            return scopes;
        }

        public Instant getExpiresAt() {
            return expiresAt;
        }
    }
}
