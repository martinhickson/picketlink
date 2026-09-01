package org.picketlink.auth.oauth.issuance;

import java.util.Set;

/**
 * When a client registers an audience allow-list, every requested audience must be on it.
 * Prevents a compromised REST client from minting tokens aimed at other resource servers.
 */
public final class AudiencePinningRule implements IssuanceRule {

    @Override
    public void enforce(IssuanceContext context) {
        Set<String> allowed = context.getClient().getAllowedAudiences();
        if (allowed.isEmpty()) {
            return;
        }
        for (String audience : context.getRequestedAudiences()) {
            if (!allowed.contains(audience)) {
                throw new IssuancePolicyException(
                        "Audience '" + audience + "' is not allowed for client "
                                + context.getClient().getClientId());
            }
        }
    }
}
