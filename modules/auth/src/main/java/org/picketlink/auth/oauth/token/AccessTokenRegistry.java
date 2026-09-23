package org.picketlink.auth.oauth.token;

import java.util.Optional;
import org.picketlink.auth.oauth.model.AccessTokenRecord;

public interface AccessTokenRegistry {

    void store(AccessTokenRecord token);

    Optional<AccessTokenRecord> findByTokenValue(String tokenValue);

    void remove(String tokenValue);

    /**
     * Drops live tokens for this subject at this client. Tokens stored with no subject
     * stay until they expire.
     */
    void revokeSubjectClient(String subject, String clientId);
}
