package org.picketlink.auth.oauth.grant;

import java.util.Set;

public interface ResourceOwnerAuthenticator {

    ResourceOwner authenticate(String username, String password);

    final class ResourceOwner {
        private final String subject;
        private final Set<String> scopes;

        public ResourceOwner(String subject, Set<String> scopes) {
            this.subject = subject;
            this.scopes = Set.copyOf(scopes);
        }

        public String getSubject() {
            return subject;
        }

        public Set<String> getScopes() {
            return scopes;
        }
    }
}
