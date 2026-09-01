package org.picketlink.oidc.provider;

import java.time.Clock;

import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;

/**
 * Production OIDC provider assembled on the managed JWT issuance core: authorization codes
 * with mandatory-PKCE support, refresh tokens with rotation and reuse detection, ID tokens
 * and access tokens signed by the {@code JwtIssuanceManager} chokepoint, discovery and
 * UserInfo. This replaces the {@code Demo*} CXF wiring as the supported provider path.
 */
public final class OidcProviderServer {

    private final String issuer;
    private final ManagedIssuanceServer issuanceServer;
    private final SubjectAuthenticator subjectAuthenticator;
    private final ClaimSource claimSource;
    private final AuthorizationCodeService authorizationCodes;
    private final RefreshTokenService refreshTokens;
    private final Clock clock;

    private OidcProviderServer(Builder builder) {
        this.issuer = builder.issuer;
        this.issuanceServer = builder.issuanceServer;
        this.subjectAuthenticator = builder.subjectAuthenticator;
        this.claimSource = builder.claimSource != null
                ? builder.claimSource
                : (builder.subjectAuthenticator instanceof ClaimSource)
                        ? (ClaimSource) builder.subjectAuthenticator
                        : NO_CLAIMS;
        this.clock = builder.clock == null ? Clock.systemUTC() : builder.clock;
        this.authorizationCodes = builder.authorizationCodes != null
                ? builder.authorizationCodes
                : new AuthorizationCodeService(this.clock);
        this.refreshTokens = builder.refreshTokens != null
                ? builder.refreshTokens
                : new RefreshTokenService(this.clock);
    }

    public String getIssuer() {
        return issuer;
    }

    public ManagedIssuanceServer getIssuanceServer() {
        return issuanceServer;
    }

    public SubjectAuthenticator getSubjectAuthenticator() {
        return subjectAuthenticator;
    }

    /** Claim source for ID tokens / UserInfo; never null. */
    public ClaimSource getClaimSource() {
        return claimSource;
    }

    public AuthorizationCodeService getAuthorizationCodes() {
        return authorizationCodes;
    }

    public RefreshTokenService getRefreshTokens() {
        return refreshTokens;
    }

    public Clock getClock() {
        return clock;
    }

    public static Builder builder(String issuer, ManagedIssuanceServer issuanceServer) {
        return new Builder(issuer, issuanceServer);
    }

    /** Authenticator used when none is configured: rejects every login attempt. */
    public static final SubjectAuthenticator DENY_ALL = new SubjectAuthenticator() {
        @Override
        public java.util.Optional<String> authenticate(String username, String password) {
            return java.util.Optional.empty();
        }
    };

    /** Claim source used when none is configured and the authenticator is not one. */
    public static final ClaimSource NO_CLAIMS = new ClaimSource() {
        @Override
        public java.util.Map<String, Object> claimsFor(String subject) {
            return java.util.Collections.emptyMap();
        }
    };

    public static final class Builder {

        private final String issuer;
        private final ManagedIssuanceServer issuanceServer;
        private SubjectAuthenticator subjectAuthenticator = DENY_ALL;
        private ClaimSource claimSource;
        private AuthorizationCodeService authorizationCodes;
        private RefreshTokenService refreshTokens;
        private Clock clock;

        private Builder(String issuer, ManagedIssuanceServer issuanceServer) {
            this.issuer = issuer;
            this.issuanceServer = issuanceServer;
        }

        public Builder subjectAuthenticator(SubjectAuthenticator authenticator) {
            this.subjectAuthenticator = authenticator;
            return this;
        }

        public Builder claimSource(ClaimSource claimSource) {
            this.claimSource = claimSource;
            return this;
        }

        public Builder authorizationCodes(AuthorizationCodeService service) {
            this.authorizationCodes = service;
            return this;
        }

        public Builder refreshTokens(RefreshTokenService service) {
            this.refreshTokens = service;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public OidcProviderServer build() {
            return new OidcProviderServer(this);
        }
    }
}
