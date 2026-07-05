package org.picketlink.oidc;

import java.util.Arrays;
import java.util.List;

public final class OidcDemoConstants {

    public static final String CLIENT_ID = "demo-rp-client";
    public static final String CLIENT_SECRET = "demo-rp-secret";
    public static final String OPENID_SCOPE = "openid";
    public static final String PROFILE_SCOPE = "profile";
    public static final List<String> DEFAULT_SCOPES = Arrays.asList(OPENID_SCOPE, PROFILE_SCOPE);

    public static final String DEMO_USERNAME = "user1";
    public static final String DEMO_PASSWORD = "password1";
    public static final String DEMO_ROLE = "role1";

    public static final String KEYSTORE_ALIAS = "servercert";
    public static final String KEYSTORE_PASSWORD = "store123";
    public static final String KEYSTORE_KEY_PASSWORD = "test123";
    public static final String KEYSTORE_TYPE = "jks";

    private OidcDemoConstants() {
    }
}
