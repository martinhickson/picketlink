package org.picketlink.auth.oauth.issuance;

import java.util.Set;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;

/** Result of a successful issuance. */
public final class IssuedToken {

    private final String tokenValue;
    private final String tokenId;
    private final long lifetimeSeconds;
    private final Set<String> scopes;
    private final JwtClaims claims;

    public IssuedToken(String tokenValue, String tokenId, long lifetimeSeconds, Set<String> scopes) {
        this(tokenValue, tokenId, lifetimeSeconds, scopes, null);
    }

    public IssuedToken(String tokenValue, String tokenId, long lifetimeSeconds, Set<String> scopes,
            JwtClaims claims) {
        this.tokenValue = tokenValue;
        this.tokenId = tokenId;
        this.lifetimeSeconds = lifetimeSeconds;
        this.scopes = Set.copyOf(scopes);
        this.claims = claims;
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public String getTokenId() {
        return tokenId;
    }

    public long getLifetimeSeconds() {
        return lifetimeSeconds;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    /** The signed claims (subject, nonce, ...); may be null for the legacy issuer path. */
    public JwtClaims getClaims() {
        return claims;
    }
}
