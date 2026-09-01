package org.picketlink.auth.oauth.admin;

import java.io.IOException;
import java.util.Arrays;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import org.picketlink.auth.oauth.issuance.JwtIssuanceManager;

/**
 * Protects the admin API: every request must carry a bearer JWT (validated through the
 * {@link JwtIssuanceManager} chokepoint, so signature/expiry/revocation all apply) that grants
 * the required scope.
 */
@Priority(Priorities.AUTHENTICATION)
public class AdminScopeFilter implements ContainerRequestFilter {

    public static final String ADMIN_SCOPE = "auth-admin";

    private final JwtIssuanceManager issuanceManager;
    private final String requiredScope;

    public AdminScopeFilter(JwtIssuanceManager issuanceManager) {
        this(issuanceManager, ADMIN_SCOPE);
    }

    public AdminScopeFilter(JwtIssuanceManager issuanceManager, String requiredScope) {
        this.issuanceManager = issuanceManager;
        this.requiredScope = requiredScope;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String authorization = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            abort(requestContext, "Admin access requires a bearer token");
            return;
        }
        try {
            Object scope = issuanceManager.validate(authorization.substring(7).trim())
                    .getClaim(JwtIssuanceManager.CLAIM_SCOPE);
            if (scope == null || !Arrays.asList(scope.toString().split(" ")).contains(requiredScope)) {
                abort(requestContext, "Bearer token does not grant the '" + requiredScope + "' scope");
            }
        } catch (RuntimeException ex) {
            abort(requestContext, ex.getMessage());
        }
    }

    private static void abort(ContainerRequestContext requestContext, String errorDescription) {
        requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE,
                        "Bearer error=\"insufficient_scope\", error_description=\""
                                + errorDescription + "\"")
                .build());
    }
}
