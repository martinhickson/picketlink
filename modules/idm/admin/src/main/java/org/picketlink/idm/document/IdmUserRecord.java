package org.picketlink.idm.document;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public final class IdmUserRecord {

    private final String id;
    private final String loginName;
    private final String passwordHash;
    private final List<String> roles;
    private final boolean enabled;

    public IdmUserRecord(String id, String loginName, String passwordHash, List<String> roles, boolean enabled) {
        this.id = Objects.requireNonNull(id, "id");
        this.loginName = Objects.requireNonNull(loginName, "loginName");
        this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash");
        this.roles = Collections.unmodifiableList(new ArrayList<String>(roles));
        this.enabled = enabled;
    }

    public static IdmUserRecord createNew(String loginName, String passwordHash, List<String> roles) {
        return new IdmUserRecord(UUID.randomUUID().toString(), loginName, passwordHash, roles, true);
    }

    public IdmUserRecord withPasswordHash(String newHash) {
        return new IdmUserRecord(id, loginName, newHash, roles, enabled);
    }

    public IdmUserRecord withRoles(List<String> newRoles) {
        return new IdmUserRecord(id, loginName, passwordHash, newRoles, enabled);
    }

    public IdmUserRecord withEnabled(boolean newEnabled) {
        return new IdmUserRecord(id, loginName, passwordHash, roles, newEnabled);
    }

    public String getId() {
        return id;
    }

    public String getLoginName() {
        return loginName;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public List<String> getRoles() {
        return roles;
    }

    public boolean isEnabled() {
        return enabled;
    }
}
