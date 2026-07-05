package org.picketlink.oidc;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import java.security.Principal;
import java.util.List;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthRedirectionState;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oidc.idp.OidcAuthorizationCodeService;

/**
 * WildFly FORM login authenticates via {@link HttpServletRequest#getUserPrincipal()} but CXF
 * OAuth authorize only resolves the end-user when JAX-RS {@link SecurityContext} has a principal.
 */
public final class DemoOidcAuthorizationCodeService extends OidcAuthorizationCodeService {

    @Override
    protected Response startAuthorization(MultivaluedMap<String, String> params) {
        bridgeServletPrincipalToSecurityContext();
        return super.startAuthorization(params);
    }

    @Override
    protected Response createGrant(OAuthRedirectionState state,
            Client client,
            List<String> requestedScope,
            List<String> approvedScope,
            UserSubject userSubject,
            ServerAccessToken preauthorizedToken) {
        return super.createGrant(state, client, requestedScope, approvedScope,
                requireUserSubject(userSubject), preauthorizedToken);
    }

    @Override
    public ServerAuthorizationCodeGrant getGrantRepresentation(OAuthRedirectionState state,
            Client client,
            List<String> requestedScope,
            List<String> approvedScope,
            UserSubject userSubject,
            ServerAccessToken preauthorizedToken) {
        return super.getGrantRepresentation(state, client, requestedScope, approvedScope,
                requireUserSubject(userSubject), preauthorizedToken);
    }

    private UserSubject requireUserSubject(UserSubject userSubject) throws OAuthServiceException {
        if (userSubject != null) {
            return userSubject;
        }
        UserSubject resolved = resolveSubjectFromServlet();
        if (resolved == null) {
            throw new OAuthServiceException(new org.apache.cxf.rs.security.oauth2.common.OAuthError(
                    org.apache.cxf.rs.security.oauth2.utils.OAuthConstants.ACCESS_DENIED));
        }
        return resolved;
    }

    private UserSubject resolveSubjectFromServlet() {
        bridgeServletPrincipalToSecurityContext();
        try {
            return createUserSubject(null, null);
        } catch (OAuthServiceException ex) {
            return null;
        }
    }

    private void bridgeServletPrincipalToSecurityContext() {
        MessageContext mc = getMessageContext();
        if (mc == null) {
            return;
        }
        Object existing = mc.get(SecurityContext.class.getName());
        if (existing instanceof SecurityContext sc && sc.getUserPrincipal() != null) {
            return;
        }
        HttpServletRequest request = mc.getHttpServletRequest();
        if (request == null || request.getUserPrincipal() == null) {
            return;
        }
        SecurityContext ctx = new ServletSecurityContext(request);
        mc.put(SecurityContext.class.getName(), ctx);
        mc.put(SecurityContext.class, ctx);
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
