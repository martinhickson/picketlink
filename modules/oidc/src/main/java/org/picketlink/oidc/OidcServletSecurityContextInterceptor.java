package org.picketlink.oidc;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.SecurityContext;
import java.security.Principal;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.transport.http.AbstractHTTPDestination;

/**
 * WildFly FORM login sets {@link HttpServletRequest#getUserPrincipal()} but CXF's JAX-RS
 * {@link SecurityContext} is often empty. OAuth authorize auto-consent then creates code grants
 * with a null {@code UserSubject}.
 */
public final class OidcServletSecurityContextInterceptor extends AbstractPhaseInterceptor<Message> {

    public OidcServletSecurityContextInterceptor() {
        super(Phase.PRE_INVOKE);
    }

    @Override
    public void handleMessage(Message message) {
        Object existing = message.get(SecurityContext.class);
        if (existing instanceof SecurityContext sc && sc.getUserPrincipal() != null) {
            return;
        }
        HttpServletRequest request = (HttpServletRequest) message.get(AbstractHTTPDestination.HTTP_REQUEST);
        if (request == null || request.getUserPrincipal() == null) {
            return;
        }
        SecurityContext ctx = new ServletSecurityContext(request);
        message.put(SecurityContext.class, ctx);
        message.put(SecurityContext.class.getName(), ctx);
    }

    private static final class ServletSecurityContext implements SecurityContext {

        private final HttpServletRequest request;

        private ServletSecurityContext(HttpServletRequest request) {
            this.request = request;
        }

        @Override
        public Principal getUserPrincipal() {
            return request.getUserPrincipal();
        }

        @Override
        public boolean isUserInRole(String role) {
            return request.isUserInRole(role);
        }

        @Override
        public boolean isSecure() {
            return request.isSecure();
        }

        @Override
        public String getAuthenticationScheme() {
            return SecurityContext.FORM_AUTH;
        }
    }
}
