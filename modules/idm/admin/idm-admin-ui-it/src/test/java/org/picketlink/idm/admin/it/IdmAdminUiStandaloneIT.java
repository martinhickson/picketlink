package org.picketlink.idm.admin.it;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.idm.admin.it.deployment.IdmAdminDeployments;
import org.picketlink.idm.admin.it.support.HttpSupport;
import org.picketlink.idm.admin.it.support.TestEndpoints;

@RunWith(Arquillian.class)
@RunAsClient
public class IdmAdminUiStandaloneIT {

    @Deployment(testable = false)
    public static WebArchive deployAdminWar() {
        return IdmAdminDeployments.adminWar();
    }

    @Test
    public void servesAngularAdminUi() throws Exception {
        String body = HttpSupport.executeBody(new HttpGet(TestEndpoints.baseUrl() + "/idm-admin/index.html"));
        assertTrue("IDM admin UI should be served", body.contains("<html") || body.contains("app-root"));
    }

    @Test
    public void listsConfigurationProfiles() throws Exception {
        String profiles = HttpSupport.executeBody(new HttpGet(TestEndpoints.baseUrl() + "/api/idm/standalone/profiles"));
        assertTrue(profiles.contains("OIDC_AUTHORIZATION_SERVER"));
        assertTrue(profiles.contains("SAML"));
        assertTrue(profiles.contains("OIDC_RELYING_PARTY"));
    }

    @Test
    public void appliesOidcProfileToStagedStandaloneXml() throws Exception {
        String jbossHome = TestEndpoints.jbossHome();
        Path standalone = Path.of(jbossHome, "standalone/configuration/standalone.xml");
        String before = Files.readString(standalone);

        String applyUrl = TestEndpoints.baseUrl() + "/api/idm/standalone/apply?profile=OIDC_AUTHORIZATION_SERVER"
                + "&jbossHome=" + URLEncoder.encode(jbossHome, StandardCharsets.UTF_8);
        assertEquals(200, HttpSupport.executeStatus(new HttpPost(applyUrl)));

        String after = Files.readString(standalone);
        assertTrue(after.contains("PicketLinkOidcAsElytronDomain"));
        assertTrue(after.contains("PicketLinkOidcAsDomain"));
        assertTrue(before.contains("<security-domains>"));
        assertTrue(after.contains("<security-domains>"));

        try (Stream<Path> backups = Files.list(standalone.getParent())) {
            assertTrue("Expected timestamped standalone.xml backup",
                    backups.anyMatch(path -> path.getFileName().toString().startsWith("standalone.xml.bak-")));
        }

        String afterFirstApply = Files.readString(standalone);
        assertEquals(200, HttpSupport.executeStatus(new HttpPost(applyUrl)));
        assertEquals("Second apply should not duplicate Elytron fragments", afterFirstApply, Files.readString(standalone));
    }
}
