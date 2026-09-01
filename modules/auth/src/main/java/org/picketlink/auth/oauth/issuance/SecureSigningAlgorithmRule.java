package org.picketlink.auth.oauth.issuance;

import java.util.Set;

/**
 * Rejects tokens that would be signed with an algorithm outside the configured allow-list and
 * always rejects {@code none}. Prevents algorithm downgrade and confusion attacks.
 */
public final class SecureSigningAlgorithmRule implements IssuanceRule {

    private final Set<String> allowedAlgorithms;

    public SecureSigningAlgorithmRule(Set<String> allowedAlgorithms) {
        if (allowedAlgorithms == null || allowedAlgorithms.isEmpty()) {
            throw new IllegalArgumentException("At least one allowed algorithm is required");
        }
        this.allowedAlgorithms = Set.copyOf(allowedAlgorithms);
    }

    @Override
    public void enforce(IssuanceContext context) {
        String algorithm = context.getAlgorithm();
        if (algorithm == null || algorithm.isBlank() || "none".equalsIgnoreCase(algorithm)) {
            throw new IssuancePolicyException("Unsigned tokens are not permitted");
        }
        if (!allowedAlgorithms.contains(algorithm)) {
            throw new IssuancePolicyException(
                    "Signing algorithm " + algorithm + " is not allowed by issuance policy");
        }
    }
}
