package org.picketlink.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.grants.owner.ResourceOwnerLoginHandler;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;

/**
 * Password-grant login against the users supplied when the authorization server was mounted.
 */
public final class ConfiguredResourceOwnerLoginHandler implements ResourceOwnerLoginHandler {

    private final List<OidcUserRegistration> users;

    public ConfiguredResourceOwnerLoginHandler(List<OidcUserRegistration> users) {
        this.users = users == null ? List.of() : List.copyOf(users);
    }

    @Override
    public UserSubject createSubject(Client client, String login, String password) {
        if (login == null || password == null) {
            throw new OAuthServiceException(OAuthConstants.INVALID_GRANT);
        }
        for (OidcUserRegistration user : users) {
            if (user.getLogin().equals(login)) {
                if (!MessageDigest.isEqual(utf8(user.getPassword()), utf8(password))) {
                    throw new OAuthServiceException(OAuthConstants.INVALID_GRANT);
                }
                return new UserSubject(login, user.getRoles());
            }
        }
        throw new OAuthServiceException(OAuthConstants.INVALID_GRANT);
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
