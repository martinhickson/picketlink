package org.picketlink.auth.oauth.issuance;

import org.jboss.logging.Logger;

/** Writes issuance decisions to the security audit log. */
public final class LoggingIssuanceAuditListener implements IssuanceAuditListener {

    private static final Logger LOG = Logger.getLogger("org.picketlink.audit.issuance");

    @Override
    public void onEvent(IssuanceAuditEvent event) {
        if (event.getOutcome() == IssuanceAuditEvent.Outcome.ISSUED) {
            LOG.infof("JWT issued: %s", event);
        } else {
            LOG.warnf("JWT issuance rejected: %s", event);
        }
    }
}
