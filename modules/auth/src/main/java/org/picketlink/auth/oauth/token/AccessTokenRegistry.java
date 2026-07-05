package org.picketlink.auth.oauth.token;

import java.util.Optional;
import org.picketlink.auth.oauth.model.AccessTokenRecord;

public interface AccessTokenRegistry {

    void store(AccessTokenRecord token);

    Optional<AccessTokenRecord> findByTokenValue(String tokenValue);

    void remove(String tokenValue);
}
