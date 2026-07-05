package org.picketlink.idm.admin.it;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.idm.admin.it.deployment.IdmAdminDeployments;
import org.picketlink.idm.admin.it.support.HttpSupport;
import org.picketlink.idm.admin.it.support.ScimMockServer;
import org.picketlink.idm.admin.it.support.TestEndpoints;

@RunWith(Arquillian.class)
@RunAsClient
public class IdmAdminUiScimIT {

    @Deployment(testable = false)
    public static WebArchive deployAdminWar() {
        return IdmAdminDeployments.adminWar();
    }

    @BeforeClass
    public static void startScimServer() throws Exception {
        ScimMockServer.start();
    }

    @AfterClass
    public static void stopScimServer() {
        ScimMockServer.stop();
    }

    @Test
    public void savesScimProviderConfigThroughApi() throws Exception {
        String saveUrl = configUrl(ScimMockServer.baseUrl(), false);
        assertEquals(200, HttpSupport.executeStatus(new HttpPost(saveUrl)));

        String config = HttpSupport.executeBody(new HttpGet(TestEndpoints.baseUrl() + "/api/idm/realm/config"));
        assertTrue(config.contains("\"provider\":\"scim\""));
        assertTrue(config.contains(ScimMockServer.baseUrl()));
    }

    @Test
    public void loadsUsersGroupsAndRolesFromScimBackend() throws Exception {
        configureScimProvider();

        String realm = HttpSupport.executeBody(new HttpGet(TestEndpoints.baseUrl() + "/api/idm/realm/users"));
        assertTrue(realm.contains("\"provider\":\"scim\""));
        assertTrue(realm.contains("\"loginName\":\"alice\""));
        assertTrue(realm.contains("administrator"));
        assertTrue(realm.contains("developers"));
    }

    @Test
    public void createsUserThroughScimBackend() throws Exception {
        configureScimProvider();

        String createUrl = TestEndpoints.baseUrl() + "/api/idm/realm/users?version=0&loginName=bob&password=secret&roles=role2";
        assertEquals(201, HttpSupport.executeStatus(new HttpPost(createUrl)));

        String realm = HttpSupport.executeBody(new HttpGet(TestEndpoints.baseUrl() + "/api/idm/realm/users"));
        assertTrue(realm.contains("\"loginName\":\"bob\""));
        assertEquals(2, ScimMockServer.users().size());
    }

    private static void configureScimProvider() throws Exception {
        String saveUrl = configUrl(ScimMockServer.baseUrl(), false);
        assertEquals(200, HttpSupport.executeStatus(new HttpPost(saveUrl)));
    }

    private static String configUrl(String scimBaseUrl, boolean useDefaultBaseUrl) throws Exception {
        return TestEndpoints.baseUrl() + "/api/idm/realm/config?provider=scim"
                + "&useDefaultBaseUrl=" + useDefaultBaseUrl
                + "&syncToDocument=false"
                + "&scimBaseUrl=" + URLEncoder.encode(scimBaseUrl, StandardCharsets.UTF_8);
    }
}
