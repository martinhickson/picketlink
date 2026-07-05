package org.picketlink.idm.admin.standalone;

import java.util.Collections;
import java.util.List;

public enum WildFlyConfigurationProfile {

    SAML("SAML federation (IdP + SP Elytron)",
            "Adds PicketLink SAML Elytron realms, mechanism factories, and Undertow application-security-domains "
                    + "documented in saml-setup.md section 6.4.",
            true,
            true,
            ElytronProfileFragments.samlInsertions()),

    OIDC_AUTHORIZATION_SERVER("OIDC Authorization Server",
            "Adds FORM Elytron authentication for the OIDC AS documented in oidc-setup.md section 6.4.",
            true,
            true,
            ElytronProfileFragments.oidcAuthorizationServerInsertions()),

    OIDC_RELYING_PARTY("OIDC Relying Party",
            "No Elytron standalone.xml changes are required on the RP. Protection is handled in-application "
                    + "via the CXF OIDC client filter. Install the org.picketlink WildFly module only if you "
                    + "also deploy SAML components on this host.",
            false,
            false,
            Collections.emptyList());

    private final String title;
    private final String description;
    private final boolean mutatesStandaloneXml;
    private final boolean requiresWildFlyModule;
    private final List<XmlInsertion> insertions;

    WildFlyConfigurationProfile(String title, String description, boolean mutatesStandaloneXml,
            boolean requiresWildFlyModule, List<XmlInsertion> insertions) {
        this.title = title;
        this.description = description;
        this.mutatesStandaloneXml = mutatesStandaloneXml;
        this.requiresWildFlyModule = requiresWildFlyModule;
        this.insertions = insertions;
    }

    public String getId() {
        return name();
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public boolean isMutatesStandaloneXml() {
        return mutatesStandaloneXml;
    }

    public boolean isRequiresWildFlyModule() {
        return requiresWildFlyModule;
    }

    public List<XmlInsertion> getInsertions() {
        return insertions;
    }

    public static WildFlyConfigurationProfile fromId(String id) {
        return WildFlyConfigurationProfile.valueOf(id);
    }

    public static List<WildFlyConfigurationProfile> all() {
        return List.of(values());
    }
}
