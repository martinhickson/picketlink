package org.picketlink.auth.oauth.issuance;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.model.AccessTokenRecord;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.token.AccessTokenRegistry;

/**
 * Central chokepoint for JWT issuance on REST endpoints: every token is policy-checked, signed,
 * registered and audited here; every validation is signature-, time- and revocation-checked here.
 *
 * <p>When an {@link AccessTokenRegistry} is configured, issued tokens must be present in it to
 * validate, which makes revocation (RFC 7009) effective. Deployments that need fully stateless
 * validation may omit the registry.
 */
public final class JwtIssuanceManager {

    public static final String CLAIM_CLIENT_ID = "client_id";
    public static final String CLAIM_AZP = "azp";
    public static final String CLAIM_SCOPE = "scope";

    private final String issuer;
    private final JwtSigningService signingService;
    private final IssuancePolicyEngine policyEngine;
    private final AccessTokenRegistry tokenRegistry;
    private final IssuanceAuditListener auditListener;
    private final String defaultAlgorithm;
    private final long defaultLifetimeSeconds;
    private final Clock clock;

    public JwtIssuanceManager(String issuer,
            JwtSigningService signingService,
            IssuancePolicyEngine policyEngine,
            AccessTokenRegistry tokenRegistry,
            IssuanceAuditListener auditListener,
            String defaultAlgorithm,
            long defaultLifetimeSeconds) {
        this(issuer, signingService, policyEngine, tokenRegistry, auditListener, defaultAlgorithm,
                defaultLifetimeSeconds, Clock.systemUTC());
    }

    public JwtIssuanceManager(String issuer,
            JwtSigningService signingService,
            IssuancePolicyEngine policyEngine,
            AccessTokenRegistry tokenRegistry,
            IssuanceAuditListener auditListener,
            String defaultAlgorithm,
            long defaultLifetimeSeconds,
            Clock clock) {
        this.issuer = issuer;
        this.signingService = signingService;
        this.policyEngine = policyEngine;
        this.tokenRegistry = tokenRegistry;
        this.auditListener = auditListener == null ? IssuanceAuditListener.NOOP : auditListener;
        this.defaultAlgorithm = defaultAlgorithm;
        this.defaultLifetimeSeconds = defaultLifetimeSeconds;
        this.clock = clock;
    }

    public IssuedToken issue(IssuanceRequest request) {
        RegisteredClient client = request.getClient();
        long requestedLifetime = request.getRequestedLifetimeSeconds() != null
                ? request.getRequestedLifetimeSeconds()
                : defaultLifetimeSeconds;
        IssuanceContext context = new IssuanceContext(client, request.getGrantType(),
                request.getScopes(), request.getAudiences(), requestedLifetime, defaultAlgorithm);
        try {
            policyEngine.enforce(context);
        } catch (RuntimeException ex) {
            audit(context, null, ex);
            throw ex;
        }

        Instant issuedAt = clock.instant();
        Instant expiresAt = issuedAt.plusSeconds(context.getLifetimeSeconds());
        String tokenId = UUID.randomUUID().toString();

        JwtClaims claims = new JwtClaims();
        claims.setIssuer(getIssuer());
        String subject = request.getSubject() != null ? request.getSubject() : client.getClientId();
        claims.setSubject(subject);
        claims.setClaim(CLAIM_CLIENT_ID, client.getClientId());
        claims.setClaim(CLAIM_AZP, client.getClientId());
        if (!request.getScopes().isEmpty()) {
            claims.setClaim(CLAIM_SCOPE, String.join(" ", request.getScopes()));
        }
        if (request.getNonce() != null) {
            claims.setClaim("nonce", request.getNonce());
        }
        if (!request.getAudiences().isEmpty()) {
            claims.setAudiences(new LinkedHashSet<>(request.getAudiences()).stream().toList());
        }
        claims.setIssuedAt(issuedAt.getEpochSecond());
        claims.setExpiryTime(expiresAt.getEpochSecond());
        claims.setTokenId(tokenId);

        String tokenValue = signingService.sign(claims, context.getAlgorithm());
        if (tokenRegistry != null) {
            tokenRegistry.store(new AccessTokenRecord(tokenValue, client.getClientId(),
                    request.getScopes(), issuedAt, expiresAt));
        }
        audit(context, tokenId, null);
        return new IssuedToken(tokenValue, tokenId, context.getLifetimeSeconds(), request.getScopes(),
                claims);
    }

    /**
     * Validates a bearer token: signature, issuer, expiry, accepted algorithms and (when a
     * registry is configured) that the token has not been revoked.
     */
    public JwtClaims validate(String tokenValue) {
        JwtClaims claims = signingService.validate(tokenValue, Set.of(defaultAlgorithm));
        if (tokenRegistry != null) {
            Optional<AccessTokenRecord> record = tokenRegistry.findByTokenValue(tokenValue);
            if (record.isEmpty() || record.get().isExpired(clock.instant())) {
                throw new org.picketlink.auth.oauth.jwt.JwtValidationException(
                        "Token is revoked or was not issued by this server");
            }
        }
        return claims;
    }

    /** Revokes a token (RFC 7009). Idempotent. Only effective when a registry is configured. */
    public boolean revoke(String tokenValue) {
        if (tokenValue == null || tokenRegistry == null) {
            return false;
        }
        boolean known = tokenRegistry.findByTokenValue(tokenValue).isPresent();
        tokenRegistry.remove(tokenValue);
        return known;
    }

    /**
     * Revokes a token only if it belongs to the given client (RFC 7009 §2.1: clients may only
     * revoke their own tokens).
     */
    public boolean revoke(String tokenValue, String clientId) {
        if (tokenValue == null || clientId == null || tokenRegistry == null) {
            return false;
        }
        Optional<AccessTokenRecord> record = tokenRegistry.findByTokenValue(tokenValue);
        if (record.isEmpty() || !clientId.equals(record.get().getClientId())) {
            return false;
        }
        tokenRegistry.remove(tokenValue);
        return true;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getDefaultAlgorithm() {
        return defaultAlgorithm;
    }

    public JwtSigningService getSigningService() {
        return signingService;
    }

    private void audit(IssuanceContext context, String tokenId, RuntimeException rejection) {
        try {
            if (rejection == null) {
                auditListener.onEvent(IssuanceAuditEvent.issued(context, tokenId));
            } else {
                auditListener.onEvent(IssuanceAuditEvent.rejected(context, rejection.getMessage()));
            }
        } catch (RuntimeException ignored) {
            // auditors must never break issuance
        }
    }

    /** Convenience factory with the recommended default policy rules. */
    public static JwtIssuanceManager withDefaultPolicy(String issuer,
            JwtSigningService signingService,
            AccessTokenRegistry tokenRegistry,
            IssuanceAuditListener auditListener,
            String defaultAlgorithm,
            long defaultLifetimeSeconds,
            long maxLifetimeSeconds) {
        return new JwtIssuanceManager(issuer, signingService,
                new IssuancePolicyEngine(List.of(
                        new SecureSigningAlgorithmRule(Set.of(defaultAlgorithm)),
                        new MaxTokenLifetimeRule(maxLifetimeSeconds),
                        new AudiencePinningRule())),
                tokenRegistry, auditListener, defaultAlgorithm, defaultLifetimeSeconds);
    }
}
