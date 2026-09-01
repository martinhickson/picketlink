package org.picketlink.idm.rest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.config.IdentityConfigurationBuilder;
import org.picketlink.idm.credential.Credentials;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.credential.UsernamePasswordCredentials;
import org.picketlink.idm.internal.DefaultPartitionManager;
import org.picketlink.idm.model.basic.BasicModel;
import org.picketlink.idm.model.basic.Group;
import org.picketlink.idm.model.basic.Realm;
import org.picketlink.idm.model.basic.User;

/**
 * SCIM 2.0 identity service: authorization matrix, RFC 7644 payloads, filtering, group
 * membership — and the corporate-integration guarantee that SCIM-provisioned users
 * authenticate immediately through the OIDC {@code IdmSubjectAuthenticator} path over the
 * same partition manager.
 */
@ExtendWith(MockitoExtension.class)
class ScimServletTest {

    private static final String TOKEN = "scim-service-token";

    @TempDir
    Path tempDir;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private PartitionManager partitionManager;
    private ScimServlet servlet;
    private StringWriter responseWriter;

    @BeforeEach
    void setUp() throws Exception {
        IdentityConfigurationBuilder builder = new IdentityConfigurationBuilder();
        builder.named("default").stores().file()
                .workingDirectory(Files.createTempDirectory("plk-scim").toString())
                .supportAllFeatures();
        partitionManager = new DefaultPartitionManager(builder.build());
        Realm realm = partitionManager.getPartition(Realm.class, Realm.DEFAULT_REALM);
        if (realm == null) {
            realm = new Realm(Realm.DEFAULT_REALM);
            partitionManager.add(realm);
        }
        servlet = new ScimServlet(partitionManager, new IdentityRestAccess.StaticToken(TOKEN));
        responseWriter = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    private void auth(String token) {
        lenient().when(request.getHeader("Authorization"))
                .thenReturn(token == null ? null : "Bearer " + token);
    }

    private void body(String content) throws java.io.IOException {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        when(request.getInputStream()).thenReturn(new jakarta.servlet.ServletInputStream() {
            private int position;

            @Override
            public int read() {
                return position >= bytes.length ? -1 : bytes[position++];
            }

            @Override
            public boolean isFinished() {
                return position >= bytes.length;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(jakarta.servlet.ReadListener listener) {
            }
        });
    }

    @Test
    void advertisesServiceProviderConfig() throws Exception {
        auth(TOKEN);
        when(request.getPathInfo()).thenReturn("/ServiceProviderConfig");
        servlet.doGet(request, response);
        verify(response).setStatus(200);
        String json = responseWriter.toString();
        assertTrue(json.contains("ServiceProviderConfig"));
        assertTrue(json.contains("\"filter\":{\"supported\":true"));
        assertTrue(json.contains("\"patching\":{\"supported\":false"));
    }

    @Test
    void rejectsMissingOrWrongTokenWithScimError() throws Exception {
        auth(null);
        lenient().when(request.getPathInfo()).thenReturn("/Users");
        servlet.doGet(request, response);
        verify(response).setStatus(401);
        assertTrue(responseWriter.toString().contains("urn:ietf:params:scim:api:messages:2.0:Error"));

        auth("wrong");
        servlet.doGet(request, response);
        verify(response, org.mockito.Mockito.times(2)).setStatus(401);
    }

    @Test
    void createsListsFiltersAndDeletesUsers() throws Exception {
        auth(TOKEN);
        when(request.getPathInfo()).thenReturn("/Users");
        body("{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],"
                + "\"userName\":\"jduke\",\"name\":{\"givenName\":\"Java\",\"familyName\":\"Duke\"},"
                + "\"emails\":[{\"value\":\"jduke@corp.example\",\"primary\":true}],"
                + "\"passwords\":[{\"value\":\"secret1\",\"primary\":true}]}");
        servlet.doPost(request, response);
        verify(response).setStatus(201);
        String created = responseWriter.toString();
        assertTrue(created.contains("\"userName\":\"jduke\""));
        assertTrue(created.contains("\"givenName\":\"Java\""));
        assertTrue(created.contains("jduke@corp.example"));
        assertTrue(created.contains("urn:ietf:params:scim:schemas:core:2.0:User"));

        // list with the corporate-sync filter
        lenient().when(request.getPathInfo()).thenReturn("/Users");
        lenient().when(request.getParameter("filter")).thenReturn("userName eq \"jduke\"");
        responseWriter.getBuffer().setLength(0);
        servlet.doGet(request, response);
        String list = responseWriter.toString();
        assertTrue(list.contains("\"totalResults\":1"));
        assertTrue(list.contains("jduke"));
        assertTrue(list.contains("ListResponse"));

        lenient().when(request.getParameter("filter")).thenReturn("userName eq \"nobody\"");
        responseWriter.getBuffer().setLength(0);
        servlet.doGet(request, response);
        assertTrue(responseWriter.toString().contains("\"totalResults\":0"));

        // delete by id
        String id = created.split("\"id\":\"")[1].split("\"")[0];
        when(request.getPathInfo()).thenReturn("/Users/" + id);
        lenient().when(request.getParameter("filter")).thenReturn(null);
        servlet.doDelete(request, response);
        verify(response).setStatus(204);
    }

    @Test
    void duplicateUserIsConflict() throws Exception {
        auth(TOKEN);
        when(request.getPathInfo()).thenReturn("/Users");
        body("{\"userName\":\"dupe\"}");
        servlet.doPost(request, response);
        verify(response).setStatus(201);
        body("{\"userName\":\"dupe\"}");
        servlet.doPost(request, response);
        verify(response).setStatus(409);
    }

    @Test
    void managesGroupsAndMembership() throws Exception {
        auth(TOKEN);
        when(request.getPathInfo()).thenReturn("/Users");
        body("{\"userName\":\"alice\"}");
        servlet.doPost(request, response);
        String aliceId = responseWriter.toString().split("\"id\":\"")[1].split("\"")[0];

        when(request.getPathInfo()).thenReturn("/Groups");
        body("{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],"
                + "\"displayName\":\"employees\","
                + "\"members\":[{\"value\":\"" + aliceId + "\"}]}");
        servlet.doPost(request, response);
        verify(response, org.mockito.Mockito.atLeastOnce()).setStatus(201);
        String group = responseWriter.toString();
        assertTrue(group.contains("\"displayName\":\"employees\""));
        assertTrue(group.contains("alice"));

        // membership is visible through the IDM API (what OIDC/SAML consume)
        org.picketlink.idm.IdentityManager identityManager = partitionManager.createIdentityManager();
        org.picketlink.idm.RelationshipManager relationships = partitionManager.createRelationshipManager();
        User alice = BasicModel.getUser(identityManager, "alice");
        Group employees = BasicModel.getGroup(identityManager, "employees");
        assertTrue(BasicModel.isMember(relationships, alice, employees));

        lenient().when(request.getParameter("filter")).thenReturn("displayName eq \"employees\"");
        lenient().when(request.getPathInfo()).thenReturn("/Groups");
        responseWriter.getBuffer().setLength(0);
        servlet.doGet(request, response);
        assertTrue(responseWriter.toString().contains("\"totalResults\":1"));
    }

    @Test
    void scimProvisionedUserAuthenticatesThroughIdmCredentialPipeline() throws Exception {
        // corporate IdP provisions the user over SCIM...
        auth(TOKEN);
        when(request.getPathInfo()).thenReturn("/Users");
        body("{\"userName\":\"bob\",\"passwords\":[{\"value\":\"builder\",\"primary\":true}]}");
        servlet.doPost(request, response);
        verify(response).setStatus(201);

        // ...the OIDC IdmSubjectAuthenticator logs them in over the same partition manager
        IdmAuthProbe probe = new IdmAuthProbe();
        assertTrue(probe.authenticate("bob", "builder"), "SCIM-provisioned user must authenticate");
        assertTrue(!probe.authenticate("bob", "wrong"));
    }

    @Test
    void putReplacesPasswordAndProfile() throws Exception {
        auth(TOKEN);
        when(request.getPathInfo()).thenReturn("/Users");
        body("{\"userName\":\"carol\",\"passwords\":[{\"value\":\"old\",\"primary\":true}]}");
        servlet.doPost(request, response);
        String carolId = responseWriter.toString().split("\"id\":\"")[1].split("\"")[0];

        when(request.getPathInfo()).thenReturn("/Users/" + carolId);
        body("{\"userName\":\"carol\",\"name\":{\"givenName\":\"Carol\"},"
                + "\"passwords\":[{\"value\":\"new\",\"primary\":true}]}");
        servlet.doPut(request, response);
        verify(response).setStatus(200);
        assertTrue(responseWriter.toString().contains("Carol"));

        IdmAuthProbe probe = new IdmAuthProbe();
        assertTrue(!probe.authenticate("carol", "old"));
        assertTrue(probe.authenticate("carol", "new"));
    }

    /** Same code path as the OIDC IdmSubjectAuthenticator (username/password via IDM). */
    private final class IdmAuthProbe {

        boolean authenticate(String username, String password) {
            UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(username,
                    new Password(password));
            partitionManager.createIdentityManager().validateCredentials(credentials);
            return credentials.getStatus() == Credentials.Status.VALID;
        }
    }
}
