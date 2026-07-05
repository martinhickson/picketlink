package org.picketlink.idm.realm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.picketlink.idm.document.IdmUserRecord;

public final class IdmRealmSnapshot {

    private final String documentId;
    private final long version;
    private final String provider;
    private final String scimBaseUrl;
    private final List<IdmUserRecord> users;
    private final List<String> roles;
    private final List<String> groups;

    public IdmRealmSnapshot(String documentId, long version, String provider, String scimBaseUrl,
            List<IdmUserRecord> users, List<String> roles, List<String> groups) {
        this.documentId = documentId;
        this.version = version;
        this.provider = provider;
        this.scimBaseUrl = scimBaseUrl;
        this.users = Collections.unmodifiableList(new ArrayList<IdmUserRecord>(users));
        this.roles = Collections.unmodifiableList(new ArrayList<String>(roles));
        this.groups = Collections.unmodifiableList(new ArrayList<String>(groups));
    }

    public String getDocumentId() {
        return documentId;
    }

    public long getVersion() {
        return version;
    }

    public String getProvider() {
        return provider;
    }

    public String getScimBaseUrl() {
        return scimBaseUrl;
    }

    public List<IdmUserRecord> getUsers() {
        return users;
    }

    public List<String> getRoles() {
        return roles;
    }

    public List<String> getGroups() {
        return groups;
    }
}
