package org.picketlink.auth.oauth.issuance;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * Mutable context carried through the issuance policy rules before a token is signed. Rules may
 * tighten values (e.g. clamp a lifetime) but can only relax them within what the registered
 * client allows.
 */
public final class IssuanceContext {

    private final RegisteredClient client;
    private final String grantType;
    private final Set<String> requestedScopes;
    private final Set<String> requestedAudiences;

    private long lifetimeSeconds;
    private String algorithm;

    public IssuanceContext(RegisteredClient client, String grantType,
            Set<String> requestedScopes, Set<String> requestedAudiences,
            long lifetimeSeconds, String algorithm) {
        this.client = client;
        this.grantType = grantType;
        this.requestedScopes = unmodifiable(requestedScopes);
        this.requestedAudiences = unmodifiable(requestedAudiences);
        this.lifetimeSeconds = lifetimeSeconds;
        this.algorithm = algorithm;
    }

    public RegisteredClient getClient() {
        return client;
    }

    public String getGrantType() {
        return grantType;
    }

    public Set<String> getRequestedScopes() {
        return requestedScopes;
    }

    public Set<String> getRequestedAudiences() {
        return requestedAudiences;
    }

    public long getLifetimeSeconds() {
        return lifetimeSeconds;
    }

    public void setLifetimeSeconds(long lifetimeSeconds) {
        this.lifetimeSeconds = lifetimeSeconds;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    private static Set<String> unmodifiable(Set<String> values) {
        return values == null ? Collections.emptySet() : Collections.unmodifiableSet(new LinkedHashSet<>(values));
    }
}
