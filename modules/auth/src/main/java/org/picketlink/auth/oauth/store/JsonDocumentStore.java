package org.picketlink.auth.oauth.store;

/**
 * Stores JSON documents (each an aggregate such as "clients", "policies" or "keys") with
 * optimistic locking. Implementations: {@link JdbcClobDocumentStore} (JSON in a CLOB column)
 * and in-memory for tests.
 */
public interface JsonDocumentStore {

    /**
     * @return the stored JSON document, or null when absent
     */
    String load(String documentId);

    /**
     * @return the version that must be passed to the next {@link #save(String, String, long)}
     */
    long currentVersion(String documentId);

    /**
     * Persists the document atomically.
     *
     * @param expectedVersion version previously observed via {@link #load} / {@link #currentVersion}
     * @return the new version
     * @throws DocumentConcurrentUpdateException when the document changed concurrently
     */
    long save(String documentId, String json, long expectedVersion);
}
