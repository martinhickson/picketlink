package org.picketlink.idm.admin.servlet;

import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.picketlink.idm.admin.standalone.StandaloneConfigurationResult;
import org.picketlink.idm.admin.standalone.WildFlyConfigurationProfile;

class IdmAdminJsonWriterTest {

    @Test
    void writesAvailableProfiles() {
        String json = IdmAdminJsonWriter.writeProfiles();
        assertTrue(json.startsWith("["));
        assertTrue(json.contains("\"id\":\"SAML\""));
        assertTrue(json.contains("\"id\":\"OIDC_AUTHORIZATION_SERVER\""));
        assertTrue(json.contains("\"mutatesStandaloneXml\":\"true\""));
    }

    @Test
    void writesConfigurationResult() {
        StandaloneConfigurationResult result = new StandaloneConfigurationResult(
                WildFlyConfigurationProfile.OIDC_AUTHORIZATION_SERVER,
                Path.of("/opt/wildfly/standalone/configuration/standalone.xml"),
                Path.of("/opt/wildfly/standalone/configuration/standalone.xml.bak"),
                true,
                0,
                List.of("Applied OIDC profile"));
        String json = IdmAdminJsonWriter.writeResult(result);
        assertTrue(json.contains("\"profileId\":\"OIDC_AUTHORIZATION_SERVER\""));
        assertTrue(json.contains("\"changed\":\"true\""));
        assertTrue(json.contains("Applied OIDC profile"));
    }

    @Test
    void writesErrorPayload() {
        assertTrue(IdmAdminJsonWriter.writeError("bad request").contains("\"error\":\"bad request\""));
    }
}
