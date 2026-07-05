package org.picketlink.auth.oauth.token;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.picketlink.auth.oauth.model.AccessTokenRecord;

public class InMemoryAccessTokenRegistry implements AccessTokenRegistry {

    private final Map<String, AccessTokenRecord> tokens = new ConcurrentHashMap<>();

    @Override
    public void store(AccessTokenRecord token) {
        tokens.put(token.getTokenValue(), token);
    }

    @Override
    public Optional<AccessTokenRecord> findByTokenValue(String tokenValue) {
        if (tokenValue == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(tokens.get(tokenValue));
    }

    @Override
    public void remove(String tokenValue) {
        if (tokenValue != null) {
            tokens.remove(tokenValue);
        }
    }
}
