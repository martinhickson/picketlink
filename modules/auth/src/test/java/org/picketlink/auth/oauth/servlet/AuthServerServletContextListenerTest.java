package org.picketlink.auth.oauth.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.picketlink.common.config.PicketLinkSecurityConfigPaths;

class AuthServerServletContextListenerTest {

    @AfterEach
    void clearProperties() {
        System.clearProperty("jboss.server.config.dir");
        System.clearProperty(PicketLinkSecurityConfigPaths.AUTH_CLIENTS_FILE_PROPERTY);
    }

    @Test
    void defaultAuthClientsFileUsesWildFlySecurityDirectory() {
        System.setProperty("jboss.server.config.dir", "/opt/wildfly/standalone/configuration");
        Path file = PicketLinkSecurityConfigPaths.defaultAuthClientsFile();
        assertEquals(
                Path.of("/opt/wildfly/standalone/configuration/security/picketlink-auth-clients.json"),
                file);
    }
}
