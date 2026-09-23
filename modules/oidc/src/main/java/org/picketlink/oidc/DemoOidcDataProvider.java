package org.picketlink.oidc;

import java.util.List;

/** Demo client ({@link OidcDemoConstants}) registered at one relying-party redirect. */
public class DemoOidcDataProvider extends ConfiguredOidcDataProvider {

    public DemoOidcDataProvider(String rpRedirectUri) {
        super(List.of(OidcClientRegistration.builder(
                        OidcDemoConstants.CLIENT_ID, OidcDemoConstants.CLIENT_SECRET)
                .redirectUri(rpRedirectUri)
                .scope(OidcDemoConstants.OPENID_SCOPE)
                .scope(OidcDemoConstants.PROFILE_SCOPE)
                .grantType("authorization_code")
                .grantType("refresh_token")
                .grantType("password")
                .applicationName("PicketLink Demo RP")
                .build()));
    }
}
