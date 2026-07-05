package org.picketlink.idm.admin.standalone;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class ElytronProfileFragments {

    private ElytronProfileFragments() {
    }

    static List<XmlInsertion> samlInsertions() {
        List<XmlInsertion> insertions = new ArrayList<XmlInsertion>();
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_SECURITY_DOMAINS,
                "security-domain", "PicketLinkTestElytronDomain", "saml/security-domain.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_SECURITY_REALMS,
                "custom-realm", "PicketLinkSamlRealm", "saml/custom-realm.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_SECURITY_REALMS,
                "properties-realm", "PicketLinkTestRealm", "saml/properties-realm.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_MAPPERS,
                "constant-realm-mapper", "picketlink-saml-realm-mapper", "saml/realm-mapper.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_MAPPERS,
                "constant-role-mapper", "PicketLinkTestRoleMapper", "saml/role-mapper.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_HTTP,
                "http-authentication-factory", "PicketLinkTestHttpAuth", "saml/idp-http-auth.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_HTTP,
                "http-authentication-factory", "PicketLinkSPHttpAuth", "saml/sp-http-auth.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_HTTP,
                "aggregate-http-server-mechanism-factory", "picketlink-http-mechanism-factory",
                "saml/aggregate-mechanism-factory.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_HTTP,
                "service-loader-http-server-mechanism-factory", "picketlink-saml-mechanism-factory",
                "saml/service-loader-mechanism-factory.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.UNDERTOW_APPLICATION_SECURITY_DOMAINS,
                "application-security-domain", "PicketLinkTestDomain", "saml/idp-app-security-domain.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.UNDERTOW_APPLICATION_SECURITY_DOMAINS,
                "application-security-domain", "PicketLinkSPDomain", "saml/sp-app-security-domain.xmlfrag"));
        return insertions;
    }

    static List<XmlInsertion> oidcAuthorizationServerInsertions() {
        List<XmlInsertion> insertions = new ArrayList<XmlInsertion>();
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_SECURITY_DOMAINS,
                "security-domain", "PicketLinkOidcAsElytronDomain", "oidc-as/security-domain.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_SECURITY_REALMS,
                "custom-realm", "PicketLinkOidcIdmRealm", "oidc-as/custom-realm.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_MAPPERS,
                "attribute-role-mapper", "PicketLinkOidcAsRoleMapper", "oidc-as/role-mapper.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.ELYTRON_HTTP,
                "http-authentication-factory", "PicketLinkOidcAsHttpAuth", "oidc-as/http-auth.xmlfrag"));
        insertions.add(fragment(XmlInsertion.XmlLocation.UNDERTOW_APPLICATION_SECURITY_DOMAINS,
                "application-security-domain", "PicketLinkOidcAsDomain", "oidc-as/app-security-domain.xmlfrag"));
        return insertions;
    }

    private static XmlInsertion fragment(XmlInsertion.XmlLocation location, String element, String name,
            String resourcePath) {
        return new XmlInsertion(location, element, name, readFragment(resourcePath));
    }

    private static String readFragment(String resourcePath) {
        String fullPath = "/wildfly/profiles/" + resourcePath;
        try (InputStream input = ElytronProfileFragments.class.getResourceAsStream(fullPath)) {
            if (input == null) {
                throw new IllegalStateException("Missing profile fragment: " + fullPath);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8).trim();
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to read profile fragment: " + fullPath, ex);
        }
    }
}
