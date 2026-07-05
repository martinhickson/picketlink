package org.picketlink.idm.document;

public class OptimisticLockException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final long expectedVersion;
    private final long actualVersion;

    public OptimisticLockException(String documentId, long expectedVersion, long actualVersion) {
        super("Optimistic lock failure for document " + documentId
                + ": expected version " + expectedVersion + " but was " + actualVersion);
        this.expectedVersion = expectedVersion;
        this.actualVersion = actualVersion;
    }

    public long getExpectedVersion() {
        return expectedVersion;
    }

    public long getActualVersion() {
        return actualVersion;
    }
}
