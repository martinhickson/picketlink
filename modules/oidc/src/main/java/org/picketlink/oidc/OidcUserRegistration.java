package org.picketlink.oidc;

import java.util.List;

/** End user the authorization server will accept: login, password, and roles. */
public final class OidcUserRegistration {

    private final String login;
    private final String password;
    private final List<String> roles;

    public OidcUserRegistration(String login, String password, List<String> roles) {
        if (login == null || login.isBlank()) {
            throw new IllegalArgumentException("login is required");
        }
        if (password == null) {
            throw new IllegalArgumentException("password is required");
        }
        this.login = login;
        this.password = password;
        this.roles = roles == null ? List.of() : List.copyOf(roles);
    }

    public String getLogin() {
        return login;
    }

    public String getPassword() {
        return password;
    }

    public List<String> getRoles() {
        return roles;
    }
}
