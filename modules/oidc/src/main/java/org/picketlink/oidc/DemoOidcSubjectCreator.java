package org.picketlink.oidc;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.provider.SubjectCreator;

public class DemoOidcSubjectCreator implements SubjectCreator {

    @Override
    public UserSubject createUserSubject(MessageContext mc,
            jakarta.ws.rs.core.MultivaluedMap<String, String> params)
            throws OAuthServiceException {
        HttpServletRequest request = mc.getHttpServletRequest();
        Principal principal = request == null ? null : request.getUserPrincipal();
        if (principal == null || principal.getName() == null || principal.getName().isBlank()) {
            throw new OAuthServiceException("Unauthenticated user");
        }
        UserSubject subject = new UserSubject(principal.getName(), java.util.List.of(OidcDemoConstants.DEMO_ROLE));
        return subject;
    }
}
