package org.picketlink.auth.oauth.issuance;

import java.time.Instant;
import java.util.Set;

/** Record of a single issuance (or rejection) decision, for security forensics. */
public final class IssuanceAuditEvent {

    public enum Outcome {
        ISSUED,
        REJECTED
    }

    private final Outcome outcome;
    private final String clientId;
    private final String grantType;
    private final Set<String> scopes;
    private final Set<String> audiences;
    private final long lifetimeSeconds;
    private final String algorithm;
    private final String tokenId;
    private final String reason;
    private final Instant timestamp;

    private IssuanceAuditEvent(Outcome outcome, String clientId, String grantType, Set<String> scopes,
            Set<String> audiences, long lifetimeSeconds, String algorithm, String tokenId,
            String reason, Instant timestamp) {
        this.outcome = outcome;
        this.clientId = clientId;
        this.grantType = grantType;
        this.scopes = Set.copyOf(scopes);
        this.audiences = Set.copyOf(audiences);
        this.lifetimeSeconds = lifetimeSeconds;
        this.algorithm = algorithm;
        this.tokenId = tokenId;
        this.reason = reason;
        this.timestamp = timestamp;
    }

    public static IssuanceAuditEvent issued(IssuanceContext context, String tokenId) {
        return new IssuanceAuditEvent(Outcome.ISSUED, context.getClient().getClientId(),
                context.getGrantType(), context.getRequestedScopes(), context.getRequestedAudiences(),
                context.getLifetimeSeconds(), context.getAlgorithm(), tokenId, null, Instant.now());
    }

    public static IssuanceAuditEvent rejected(IssuanceContext context, String reason) {
        return new IssuanceAuditEvent(Outcome.REJECTED, context.getClient().getClientId(),
                context.getGrantType(), context.getRequestedScopes(), context.getRequestedAudiences(),
                context.getLifetimeSeconds(), context.getAlgorithm(), null, reason, Instant.now());
    }

    public Outcome getOutcome() {
        return outcome;
    }

    public String getClientId() {
        return clientId;
    }

    public String getGrantType() {
        return grantType;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public Set<String> getAudiences() {
        return audiences;
    }

    public long getLifetimeSeconds() {
        return lifetimeSeconds;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getTokenId() {
        return tokenId;
    }

    public String getReason() {
        return reason;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return "IssuanceAuditEvent{" + outcome + " client=" + clientId + " grant=" + grantType
                + " scopes=" + scopes + " audiences=" + audiences
                + " lifetime=" + lifetimeSeconds + "s alg=" + algorithm
                + (tokenId != null ? " jti=" + tokenId : "")
                + (reason != null ? " reason=" + reason : "")
                + " at=" + timestamp + '}';
    }
}
