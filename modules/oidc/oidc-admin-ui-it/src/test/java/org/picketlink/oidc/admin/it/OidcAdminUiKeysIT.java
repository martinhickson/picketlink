package org.picketlink.oidc.admin.it;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.http.client.methods.HttpGet;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.oidc.admin.it.deployment.OidcAdminDeployments;
import org.picketlink.oidc.admin.it.support.HttpSupport;
import org.picketlink.oidc.admin.it.support.TestEndpoints;

@RunWith(Arquillian.class)
@RunAsClient
public class OidcAdminUiKeysIT {

    @Deployment(testable = false)
    public static WebArchive deployAdminWar() {
        return OidcAdminDeployments.adminWar();
    }

    @Test
    public void servesAngularAdminUi() throws Exception {
        String body = HttpSupport.executeBody(new HttpGet(TestEndpoints.baseUrl() + "/app/index.html"));
        assertTrue("OIDC admin UI should be served", body.contains("<html") || body.contains("app-root"));
    }

    @Test
    public void exposesSigningKeyStatusApi() throws Exception {
        String keys = HttpSupport.executeBody(new HttpGet(TestEndpoints.baseUrl() + "/api/keys"));
        assertEquals(200, HttpSupport.executeStatus(new HttpGet(TestEndpoints.baseUrl() + "/api/keys")));
        assertTrue(keys.contains("activeAlias"));
        assertTrue(keys.contains("generation"));
    }
}
