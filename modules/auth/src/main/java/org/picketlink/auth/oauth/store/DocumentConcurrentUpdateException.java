package org.picketlink.auth.oauth.store;

/** Thrown when a JSON document was modified concurrently (optimistic lock failure). */
public class DocumentConcurrentUpdateException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public DocumentConcurrentUpdateException(String documentId, long expectedVersion, long actualVersion) {
        super("Document '" + documentId + "' changed concurrently: expected version "
                + expectedVersion + " but was " + actualVersion);
    }
}
