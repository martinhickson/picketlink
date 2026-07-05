package org.picketlink.idm.document;

import java.io.IOException;

/**
 * Pluggable persistence for IDM realm documents (JSON envelope with optimistic locking).
 * Default implementation stores JSON on the filesystem; {@link JdbcClobIdmDocumentStore}
 * persists the same envelope in {@code picketlink_idm.picketlink_idm_clob}.
 */
public interface IdmDocumentStore {

    IdmRealmDocument load(String documentId) throws IOException;

    /**
     * @param expectedVersion document version the caller read; use {@code 0} when creating the first revision
     */
    IdmRealmDocument save(IdmRealmDocument document, long expectedVersion) throws IOException;
}
