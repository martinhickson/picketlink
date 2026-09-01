package org.picketlink.oidc.provider;

import java.util.Map;

/**
 * Optional companion to {@link SubjectAuthenticator}: supplies additional standard OIDC
 * claims (email, name, ...) for an authenticated subject, used to enrich ID tokens and the
 * UserInfo endpoint. Implementations must be read-only and cheap.
 */
public interface ClaimSource {

    /** @return claim name → value for the subject; empty when nothing is known */
    Map<String, Object> claimsFor(String subject);
}
