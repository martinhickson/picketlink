package org.picketlink.auth.oauth.issuance;

/** Receives every issuance decision. Implementations must be cheap and never throw. */
@FunctionalInterface
public interface IssuanceAuditListener {

    void onEvent(IssuanceAuditEvent event);

    /** No-op listener used when no auditor is configured. */
    IssuanceAuditListener NOOP = new IssuanceAuditListener() {
        @Override
        public void onEvent(IssuanceAuditEvent event) {
        }
    };
}
