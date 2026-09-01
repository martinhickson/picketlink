package org.picketlink.auth.oauth.issuance;

import java.util.Arrays;
import java.util.List;

/**
 * Runs the configured {@link IssuanceRule}s in order against every issuance request. The first
 * rejecting rule wins; rules may still have tightened the context before that point, which is
 * fine because no token is signed when a rule throws.
 */
public final class IssuancePolicyEngine {

    private final List<IssuanceRule> rules;

    public IssuancePolicyEngine(IssuanceRule... rules) {
        this(Arrays.asList(rules));
    }

    public IssuancePolicyEngine(List<IssuanceRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public void enforce(IssuanceContext context) {
        for (IssuanceRule rule : rules) {
            rule.enforce(context);
        }
    }
}
