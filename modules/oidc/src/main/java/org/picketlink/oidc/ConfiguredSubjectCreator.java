package org.picketlink.oidc;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.MultivaluedMap;
import java.security.Principal;
import java.util.List;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.provider.SubjectCreator;

/**
 * Builds the authorize-time subject from the container principal and the users supplied to the
 * authorization server. The password is checked by the container login; the role list comes
 * from the matching registration.
 */
public class ConfiguredSubjectCreator implements SubjectCreator {

    private final List<OidcUserRegistration> users;

    public ConfiguredSubjectCreator(List<OidcUserRegistration> users) {
        this.users = users == null ? List.of() : List.copyOf(users);
    }

    @Override
    public UserSubject createUserSubject(MessageContext messageContext,
            MultivaluedMap<String, String> params) throws OAuthServiceException {
        HttpServletRequest request = messageContext == null ? null : messageContext.getHttpServletRequest();
        Principal principal = request == null ? null : request.getUserPrincipal();
        if (principal == null || principal.getName() == null || principal.getName().isBlank()) {
            throw new OAuthServiceException("Unauthenticated user");
        }
        return subjectFor(principal.getName(), users);
    }

    static UserSubject subjectFor(String login, List<OidcUserRegistration> users) {
        for (OidcUserRegistration user : users) {
            if (user.getLogin().equals(login)) {
                return new UserSubject(login, user.getRoles());
            }
        }
        throw new OAuthServiceException("Unknown user");
    }
}
