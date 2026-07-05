package org.picketlink.auth.oauth.service;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;

public final class ScopeValidator {

    private ScopeValidator() {
    }

    public static Set<String> resolveApprovedScopes(RegisteredClient client, String requestedScope) {
        if (requestedScope == null || requestedScope.isBlank()) {
            return new LinkedHashSet<>(client.getScopes());
        }

        Set<String> requested = parseScope(requestedScope);
        if (requested.isEmpty()) {
            return new LinkedHashSet<>(client.getScopes());
        }

        Set<String> registered = client.getScopes();
        if (registered.isEmpty()) {
            return requested;
        }

        for (String scope : requested) {
            if (!registered.contains(scope)) {
                throw new OAuthException(
                        new OAuthErrorResponse(OAuthConstants.INVALID_SCOPE,
                                "Requested scope is not registered for this client"),
                        400);
            }
        }
        return requested;
    }

    public static Set<String> parseScope(String scope) {
        if (scope == null || scope.isBlank()) {
            return Collections.emptySet();
        }
        Set<String> values = new LinkedHashSet<String>();
        String[] tokens = scope.trim().split("\\s+");
        for (String token : tokens) {
            if (token != null && !token.isEmpty()) {
                values.add(token);
            }
        }
        return values;
    }

    public static String formatScope(Set<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return null;
        }
        return String.join(" ", scopes);
    }
}
