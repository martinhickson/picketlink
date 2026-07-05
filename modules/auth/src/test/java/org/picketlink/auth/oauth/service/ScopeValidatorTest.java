package org.picketlink.auth.oauth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.model.RegisteredClient;

class ScopeValidatorTest {

    @Test
    void returnsRegisteredScopesWhenRequestIsBlank() {
        RegisteredClient client = RegisteredClient.builder("demo", "secret")
                .scope("api.read")
                .scope("api.write")
                .build();

        Set<String> scopes = ScopeValidator.resolveApprovedScopes(client, null);

        assertEquals(Set.of("api.read", "api.write"), scopes);
    }

    @Test
    void acceptsRequestedSubset() {
        RegisteredClient client = RegisteredClient.builder("demo", "secret")
                .scope("api.read")
                .scope("api.write")
                .build();

        Set<String> scopes = ScopeValidator.resolveApprovedScopes(client, "api.read");

        assertEquals(Set.of("api.read"), scopes);
    }

    @Test
    void rejectsUnknownScope() {
        RegisteredClient client = RegisteredClient.builder("demo", "secret")
                .scope("api.read")
                .build();

        OAuthException ex = assertThrows(OAuthException.class,
                () -> ScopeValidator.resolveApprovedScopes(client, "admin"));
        assertEquals(OAuthConstants.INVALID_SCOPE, ex.getError().getError());
    }

    @Test
    void parsesSpaceDelimitedScopes() {
        Set<String> scopes = ScopeValidator.parseScope("openid profile email");
        assertEquals(Set.of("openid", "profile", "email"), scopes);
    }

    @Test
    void formatsScopes() {
        assertTrue(ScopeValidator.formatScope(Set.of("a", "b")).contains("a"));
    }
}
