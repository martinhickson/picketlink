package org.picketlink.oidc.provider;

/**
 * Persistence SPI behind {@link RefreshTokenService}. Implementations must store records
 * keyed by token hash and track retired (already-rotated) hashes for replay detection.
 */
public interface RefreshTokenStore {

    void save(RefreshTokenRecord record);

    /** @return the record, or null when unknown or already removed */
    RefreshTokenRecord find(String tokenHash);

    /** @return the removed record, or null when absent */
    RefreshTokenRecord remove(String tokenHash);

    /** Records a rotated-away hash so a later presentation is detected as replay. */
    void rememberRetired(String tokenHash, String family);

    /** @return the family the retired hash belonged to, or null */
    String retiredFamily(String tokenHash);

    /** Removes every live and retired token of the family (replay response). */
    void revokeFamily(String family);

    /** Removes live refresh tokens for this subject at this client. */
    void revokeSubjectClient(String subject, String clientId);

    /** In-memory default; refresh state does not survive restarts. */
    final class InMemoryRefreshTokenStore implements RefreshTokenStore {

        private final java.util.concurrent.ConcurrentHashMap<String, RefreshTokenRecord> byHash =
                new java.util.concurrent.ConcurrentHashMap<>();
        private final java.util.concurrent.ConcurrentHashMap<String, String> retired =
                new java.util.concurrent.ConcurrentHashMap<>();

        @Override
        public void save(RefreshTokenRecord record) {
            byHash.put(record.getTokenHash(), record);
        }

        @Override
        public RefreshTokenRecord find(String tokenHash) {
            return byHash.get(tokenHash);
        }

        @Override
        public RefreshTokenRecord remove(String tokenHash) {
            return byHash.remove(tokenHash);
        }

        @Override
        public void rememberRetired(String tokenHash, String family) {
            retired.put(tokenHash, family);
        }

        @Override
        public String retiredFamily(String tokenHash) {
            return retired.get(tokenHash);
        }

        @Override
        public void revokeFamily(String family) {
            for (RefreshTokenRecord record : byHash.values()) {
                if (family.equals(record.getFamily())) {
                    byHash.remove(record.getTokenHash());
                }
            }
            retired.entrySet().removeIf(entry -> family.equals(entry.getValue()));
        }

        @Override
        public void revokeSubjectClient(String subject, String clientId) {
            if (subject == null || clientId == null) {
                return;
            }
            byHash.entrySet().removeIf(entry -> clientId.equals(entry.getValue().getClientId())
                    && subject.equals(entry.getValue().getSubject()));
        }
    }
}
