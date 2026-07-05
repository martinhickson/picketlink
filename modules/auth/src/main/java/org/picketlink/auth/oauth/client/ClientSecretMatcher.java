package org.picketlink.auth.oauth.client;

public interface ClientSecretMatcher {

    boolean matches(String expectedSecret, String providedSecret);
}
