package org.picketlink.auth.oauth.rest;

import java.io.IOException;
import java.security.Principal;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.issuance.JwtIssuanceManager;
import org.picketlink.auth.oauth.jwt.JwtValidationException;

/**
 * JAX-RS bearer authentication for REST endpoints protected by PicketLink-issued JWTs. The
 * servlet-based {@code BearerJwtAuthenticationFilter} remains available for plain servlet apps;
 * this filter is the first-class JAX-RS path and shares the {@link JwtIssuanceManager}
 * validation chokepoint (signature, expiry, algorithm allow-list, revocation).
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class JwtBearerAuthenticationFilter implements ContainerRequestFilter {

    private final JwtIssuanceManager issuanceManager;

    public JwtBearerAuthenticationFilter(JwtIssuanceManager issuanceManager) {
        this.issuanceManager = issuanceManager;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String authorization = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            abort(requestContext, "Bearer token is required");
            return;
        }
        String token = authorization.substring(7).trim();
        JwtClaims claims;
        try {
            claims = issuanceManager.validate(token);
        } catch (JwtValidationException ex) {
            abort(requestContext, ex.getMessage());
            return;
        }
        String clientId = claims.getSubject();
        if (clientId == null) {
            clientId = String.valueOf(claims.getClaim(JwtIssuanceManager.CLAIM_CLIENT_ID));
        }
        final String principalName = clientId;
        requestContext.setSecurityContext(new SecurityContext() {
            @Override
            public Principal getUserPrincipal() {
                return new Principal() {
                    @Override
                    public String getName() {
                        return principalName;
                    }
                };
            }

            @Override
            public boolean isUserInRole(String role) {
                Object scope = claims.getClaim(JwtIssuanceManager.CLAIM_SCOPE);
                return scope != null && java.util.Arrays.asList(scope.toString().split(" ")).contains(role);
            }

            @Override
            public boolean isSecure() {
                return requestContext.getSecurityContext().isSecure();
            }

            @Override
            public String getAuthenticationScheme() {
                return OAuthConstants.BEARER_TOKEN_TYPE;
            }
        });
    }

    private static void abort(ContainerRequestContext requestContext, String errorDescription) {
        requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE,
                        OAuthConstants.BEARER_TOKEN_TYPE + " error=\"invalid_token\""
                                + ", error_description=\"" + errorDescription + "\"")
                .build());
    }
}
