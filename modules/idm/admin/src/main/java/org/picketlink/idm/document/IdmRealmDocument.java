package org.picketlink.idm.document;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class IdmRealmDocument {

    private final String documentId;
    private final long version;
    private final List<IdmUserRecord> users;

    public IdmRealmDocument(String documentId, long version, List<IdmUserRecord> users) {
        this.documentId = Objects.requireNonNull(documentId, "documentId");
        this.version = version;
        this.users = Collections.unmodifiableList(new ArrayList<IdmUserRecord>(users));
    }

    public static IdmRealmDocument empty(String documentId) {
        return new IdmRealmDocument(documentId, 0L, Collections.emptyList());
    }

    public IdmRealmDocument nextVersion(List<IdmUserRecord> updatedUsers) {
        return new IdmRealmDocument(documentId, version + 1L, updatedUsers);
    }

    public String getDocumentId() {
        return documentId;
    }

    public long getVersion() {
        return version;
    }

    public List<IdmUserRecord> getUsers() {
        return users;
    }
}
