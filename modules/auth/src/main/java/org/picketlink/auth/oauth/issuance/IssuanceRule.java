package org.picketlink.auth.oauth.issuance;

/**
 * A single issuance policy rule, inspired by Keycloak's client-policy executors but deliberately
 * minimal: one method, full access to the {@link IssuanceContext}.
 */
@FunctionalInterface
public interface IssuanceRule {

    /**
     * Enforces the rule against the context, tightening values or rejecting the request outright.
     *
     * @throws IssuancePolicyException to reject the request
     */
    void enforce(IssuanceContext context) throws IssuancePolicyException;
}
