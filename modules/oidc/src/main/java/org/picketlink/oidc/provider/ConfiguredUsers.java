package org.picketlink.oidc.provider;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Demo authenticator named from {@code web.xml}. The {@code users} init-param is
 * comma-separated {@code username=password} pairs.
 */
public final class ConfiguredUsers implements SubjectAuthenticator {

    public static final String INIT_PARAM_USERS = "users";

    private final SubjectAuthenticator.InMemorySubjectAuthenticator delegate;

    public ConfiguredUsers(Map<String, String> users) {
        this.delegate = new SubjectAuthenticator.InMemorySubjectAuthenticator(users);
    }

    public static Map<String, String> parse(String raw) {
        Map<String, String> users = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) {
            return users;
        }
        for (String pair : raw.split(",")) {
            String trimmed = pair.trim();
            int split = trimmed.indexOf('=');
            if (split <= 0 || split == trimmed.length() - 1) {
                continue;
            }
            users.put(trimmed.substring(0, split).trim(), trimmed.substring(split + 1));
        }
        return users;
    }

    @Override
    public Optional<String> authenticate(String username, String password) {
        return delegate.authenticate(username, password);
    }
}
