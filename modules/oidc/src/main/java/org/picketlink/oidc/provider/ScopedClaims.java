package org.picketlink.oidc.provider;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * OIDC Core 5.4: profile, email, phone, and address claims are released only when the
 * corresponding scope was granted. Other claims pass through.
 */
final class ScopedClaims {

    private static final Set<String> PROFILE = Set.of(
            "name", "family_name", "given_name", "middle_name", "nickname",
            "preferred_username", "profile", "picture", "website", "gender",
            "birthdate", "zoneinfo", "locale", "updated_at");
    private static final Set<String> EMAIL = Set.of("email", "email_verified");
    private static final Set<String> PHONE = Set.of("phone_number", "phone_number_verified");
    private static final Set<String> ADDRESS = Set.of("address");

    private ScopedClaims() {
    }

    static Map<String, Object> select(Set<String> scopes, Map<String, Object> claims) {
        Map<String, Object> selected = new LinkedHashMap<>();
        if (claims == null || claims.isEmpty()) {
            return selected;
        }
        Set<String> granted = scopes == null ? Set.of() : scopes;
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (allowed(granted, entry.getKey())) {
                selected.put(entry.getKey(), entry.getValue());
            }
        }
        return selected;
    }

    static Set<String> parse(Object scope) {
        Set<String> scopes = new LinkedHashSet<>();
        if (scope == null) {
            return scopes;
        }
        for (String part : scope.toString().split(" ")) {
            if (!part.isBlank()) {
                scopes.add(part);
            }
        }
        return scopes;
    }

    private static boolean allowed(Set<String> scopes, String claim) {
        if (PROFILE.contains(claim)) {
            return scopes.contains("profile");
        }
        if (EMAIL.contains(claim)) {
            return scopes.contains("email");
        }
        if (PHONE.contains(claim)) {
            return scopes.contains("phone");
        }
        if (ADDRESS.contains(claim)) {
            return scopes.contains("address");
        }
        return true;
    }
}
