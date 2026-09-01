package org.picketlink.oidc.provider;

import java.util.Map;
import java.util.Optional;

/**
 * Pluggable end-user authentication for the OIDC authorization endpoint. Deployments wire
 * their identity source here (IDM, LDAP, corporate SSO); {@link InMemorySubjectAuthenticator}
 * covers tests and demos.
 */
public interface SubjectAuthenticator {

    /**
     * @return the authenticated subject id (the {@code sub} claim), or empty on bad credentials
     */
    Optional<String> authenticate(String username, String password);

    /** Fixed user set — tests and demos. */
    final class InMemorySubjectAuthenticator implements SubjectAuthenticator {

        private final Map<String, String> users;

        public InMemorySubjectAuthenticator(Map<String, String> users) {
            this.users = Map.copyOf(users);
        }

        @Override
        public Optional<String> authenticate(String username, String password) {
            if (username == null || password == null) {
                return Optional.empty();
            }
            String expected = users.get(username);
            if (expected == null || !constantTimeEquals(expected, password)) {
                return Optional.empty();
            }
            return Optional.of(username);
        }

        private static boolean constantTimeEquals(String a, String b) {
            return java.security.MessageDigest.isEqual(
                    a.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    b.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }
}
