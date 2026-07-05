package org.picketlink.oidc;

import jakarta.ws.rs.container.ContainerRequestContext;
import java.io.IOException;
import org.apache.cxf.rs.security.oidc.rp.OidcClientCodeRequestFilter;

/**
 * Applies OIDC authorization-code flow only on protected JAX-RS paths so public
 * demo endpoints such as {@code /api/info} stay anonymous.
 */
public final class OidcPathScopedClientCodeRequestFilter extends OidcClientCodeRequestFilter {

    @Override
    public void filter(ContainerRequestContext context) throws IOException {
        if (requiresOidcFilter(context.getUriInfo().getPath())) {
            super.filter(context);
        }
    }

    private static boolean requiresOidcFilter(String path) {
        return "me".equals(path) || "callback".equals(path);
    }
}
