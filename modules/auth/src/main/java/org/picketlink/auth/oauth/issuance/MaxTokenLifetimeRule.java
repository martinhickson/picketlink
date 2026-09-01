package org.picketlink.auth.oauth.issuance;

/**
 * Caps token lifetime at the server-wide maximum and, when the client registered a stricter
 * per-client maximum, at that value too. Values above the cap are clamped, not rejected.
 */
public final class MaxTokenLifetimeRule implements IssuanceRule {

    private final long maxLifetimeSeconds;

    public MaxTokenLifetimeRule(long maxLifetimeSeconds) {
        if (maxLifetimeSeconds <= 0) {
            throw new IllegalArgumentException("maxLifetimeSeconds must be positive");
        }
        this.maxLifetimeSeconds = maxLifetimeSeconds;
    }

    @Override
    public void enforce(IssuanceContext context) {
        long cap = maxLifetimeSeconds;
        long clientCap = context.getClient().getMaxTokenLifetimeSeconds();
        if (clientCap > 0 && clientCap < cap) {
            cap = clientCap;
        }
        if (context.getLifetimeSeconds() <= 0) {
            throw new IssuancePolicyException("Token lifetime must be positive");
        }
        if (context.getLifetimeSeconds() > cap) {
            context.setLifetimeSeconds(cap);
        }
    }
}
