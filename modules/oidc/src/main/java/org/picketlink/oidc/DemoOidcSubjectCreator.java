package org.picketlink.oidc;

import java.util.List;

/** Demo subject creator for {@link OidcDemoConstants#DEMO_USERNAME}. */
public class DemoOidcSubjectCreator extends ConfiguredSubjectCreator {

    public DemoOidcSubjectCreator() {
        super(List.of(new OidcUserRegistration(
                OidcDemoConstants.DEMO_USERNAME,
                OidcDemoConstants.DEMO_PASSWORD,
                List.of(OidcDemoConstants.DEMO_ROLE))));
    }
}
