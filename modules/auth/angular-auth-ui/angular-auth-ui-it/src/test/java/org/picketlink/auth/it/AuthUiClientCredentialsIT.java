package org.picketlink.auth.it;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.UUID;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.auth.it.deployment.AuthUiDeployments;
import org.picketlink.auth.it.support.HttpSupport;
import org.picketlink.auth.it.support.TestEndpoints;

@RunWith(Arquillian.class)
@RunAsClient
public class AuthUiClientCredentialsIT {

    @Deployment(name = "auth", order = 1, testable = false)
    @TargetsContainer("auth-server")
    public static WebArchive deployAuthWar() {
        return AuthUiDeployments.authWar();
    }

    @Deployment(name = "api", order = 2, testable = false)
    @TargetsContainer("api-server")
    public static WebArchive deployApiWar() {
        return AuthUiDeployments.apiWar();
    }

    @Test
    public void angularUiRegistersClientAndJwtProtectsRestApi() throws Exception {
        String authBase = TestEndpoints.authBaseUrl();
        String apiBase = TestEndpoints.apiBaseUrl();

        String uiBody = HttpSupport.executeBody(new HttpGet(authBase + "/auth-ui/index.html"));
        assertTrue("Angular auth UI should be served", uiBody.contains("<html") || uiBody.contains("app-root"));

        String clientId = "it-service-" + UUID.randomUUID();
        String clientSecret = "secret-" + UUID.randomUUID();
        String registrationJson = "{"
                + "\"clientId\":\"" + clientId + "\","
                + "\"clientSecret\":\"" + clientSecret + "\","
                + "\"tokenEndpointAuthMethod\":\"client_secret_post\","
                + "\"scopes\":[\"api.read\"]"
                + "}";

        HttpPost register = new HttpPost(authBase + "/api/auth/clients");
        register.setEntity(new StringEntity(registrationJson, ContentType.APPLICATION_JSON));
        assertEquals(201, HttpSupport.executeStatus(register));

        HttpPost tokenRequest = new HttpPost(authBase + "/oauth/token");
        tokenRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
        tokenRequest.setEntity(new StringEntity(
                "grant_type=client_credentials"
                        + "&client_id=" + clientId
                        + "&client_secret=" + clientSecret
                        + "&scope=api.read",
                ContentType.APPLICATION_FORM_URLENCODED));
        String tokenResponse = HttpSupport.executeBody(tokenRequest);
        String accessToken = HttpSupport.readJsonField(tokenResponse, "access_token");
        assertNotNull("Token endpoint should return access_token", accessToken);
        assertEquals(3, accessToken.split("\\.").length);

        HttpGet version = new HttpGet(apiBase + "/version");
        version.setHeader("Authorization", "Bearer " + accessToken);
        String versionBody = HttpSupport.executeBody(version);
        assertTrue(versionBody.contains("\"version\""));

        HttpGet user = new HttpGet(apiBase + "/user");
        user.setHeader("Authorization", "Bearer " + accessToken);
        String userBody = HttpSupport.executeBody(user);
        assertTrue(userBody.contains(clientId));

        assertEquals(401, HttpSupport.executeStatus(new HttpGet(apiBase + "/version")));
    }
}
