package org.picketlink.auth.oauth.grant;

import java.time.Instant;
import java.util.Set;

@FunctionalInterface
public interface SubjectAccessTokenIssuer {

    String issue(String subject, String clientId, Set<String> scopes, Instant issuedAt);
}
