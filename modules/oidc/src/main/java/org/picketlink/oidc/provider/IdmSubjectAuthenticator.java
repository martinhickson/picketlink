package org.picketlink.oidc.provider;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.Credentials;
import org.picketlink.idm.credential.UsernamePasswordCredentials;
import org.picketlink.idm.model.basic.BasicModel;
import org.picketlink.idm.model.basic.User;

/**
 * OIDC subject authentication against PicketLink IDM — the provider's natural user store.
 * Passwords are verified through IDM's credential pipeline (hashing, encoding, updating as
 * configured), and the authenticated {@link User} also enriches ID tokens and UserInfo with
 * standard OIDC claims ({@code email}, {@code given_name}, {@code family_name},
 * {@code preferred_username}, {@code name}) via {@link #claimsFor(String)}.
 */
public final class IdmSubjectAuthenticator implements SubjectAuthenticator, ClaimSource {

    private final IdentityManager identityManager;

    public IdmSubjectAuthenticator(IdentityManager identityManager) {
        this.identityManager = identityManager;
    }

    @Override
    public Optional<String> authenticate(String username, String password) {
        if (username == null || username.isBlank() || password == null) {
            return Optional.empty();
        }
        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(username,
                new org.picketlink.idm.credential.Password(password));
        identityManager.validateCredentials(credentials);
        if (credentials.getStatus() != Credentials.Status.VALID) {
            return Optional.empty();
        }
        return Optional.of(username);
    }

    @Override
    public Map<String, String> claimsFor(String subject) {
        User user = BasicModel.getUser(identityManager, subject);
        Map<String, String> claims = new LinkedHashMap<>();
        if (user == null) {
            return claims;
        }
        putIfSet(claims, "preferred_username", user.getLoginName());
        putIfSet(claims, "email", user.getEmail());
        String firstName = user.getFirstName();
        String lastName = user.getLastName();
        if (firstName != null && lastName != null) {
            claims.put("name", firstName + " " + lastName);
        }
        putIfSet(claims, "given_name", firstName);
        putIfSet(claims, "family_name", lastName);
        return claims;
    }

    private static void putIfSet(Map<String, String> claims, String name, String value) {
        if (value != null && !value.isBlank()) {
            claims.put(name, value);
        }
    }
}
