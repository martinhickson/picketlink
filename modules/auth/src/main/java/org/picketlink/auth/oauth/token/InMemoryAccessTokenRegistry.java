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

    @Override
    public void revokeSubjectClient(String subject, String clientId) {
        if (subject == null || subject.isBlank() || clientId == null || clientId.isBlank()) {
            return;
        }
        tokens.entrySet().removeIf(entry -> subject.equals(entry.getValue().getSubject())
                && clientId.equals(entry.getValue().getClientId()));
    }
}
