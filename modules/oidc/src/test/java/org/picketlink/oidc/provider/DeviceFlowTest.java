package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;

/**
 * PL-117: Device Authorization Grant (RFC 8628) — CLI/TV flow: device requests a code,
 * user approves on the verification page, device polls until tokens arrive.
 */
@ExtendWith(MockitoExtension.class)
class DeviceFlowTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String CLIENT_ID = "cli-tool";
    private static final String CLIENT_SECRET = "cli-secret";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private DeviceAuthorizationServlet deviceAuthorization;
    private DeviceVerificationServlet verification;
    private OidcTokenEndpointServlet token;
    private StringWriter writer;

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                java.nio.file.Files.createTempDirectory("plk-device").resolve("k.p12").toString());
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(CLIENT_ID, CLIENT_SECRET)
                .scope("openid")
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer)
                .subjectAuthenticator(new SubjectAuthenticator.InMemorySubjectAuthenticator(
                        Map.of("alice", "wonderland")))
                .build();
        deviceAuthorization = new DeviceAuthorizationServlet(server);
        verification = new DeviceVerificationServlet(server);
        token = new OidcTokenEndpointServlet(server);
        writer = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(writer));
    }

    private void post(String formBody) throws java.io.IOException {
        lenient().when(request.getInputStream()).thenReturn(inputStream(formBody));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic "
                + Base64.getEncoder().encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
    }

    private static String url(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String startDeviceFlow() throws Exception {
        writer.getBuffer().setLength(0);
        post("scope=openid");
        deviceAuthorization.doPost(request, response);
        verify(response).setStatus(200);
        String json = writer.toString();
        assertTrue(json.contains("\"device_code\":\""));
        assertTrue(json.contains("\"user_code\":\""));
        assertTrue(json.contains("\"verification_uri\""));
        assertTrue(json.contains("\"interval\""));
        return json;
    }

    @Test
    void completeDeviceFlow() throws Exception {
        String grant = startDeviceFlow();
        String deviceCode = grant.split("\"device_code\":\"")[1].split("\"")[0];
        String userCode = grant.split("\"user_code\":\"")[1].split("\"")[0];

        // user approves on the verification page
        lenient().when(request.getParameter("user_code")).thenReturn(userCode);
        lenient().when(request.getParameter("username")).thenReturn("alice");
        lenient().when(request.getParameter("password")).thenReturn("wonderland");
        lenient().when(request.getParameter("decision")).thenReturn("approve");
        verification.doPost(request, response);
        assertTrue(writer.toString().contains("approved"));

        // device polls: tokens arrive for the approved subject
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        post("grant_type=" + url("urn:ietf:params:oauth:grant-type:device_code")
                + "&device_code=" + url(deviceCode));
        token.doPost(request, response);
        verify(response).setStatus(200);
        String accessToken = writer.toString().split("\"access_token\":\"")[1].split("\"")[0];
        assertEqualsSafe("alice", server.getIssuanceServer().getIssuanceManager()
                .validate(accessToken).getSubject());

        // device codes are single use: polling again reports the grant gone
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        post("grant_type=" + url("urn:ietf:params:oauth:grant-type:device_code")
                + "&device_code=" + url(deviceCode));
        token.doPost(request, response);
        verify(response).setStatus(400);
        assertTrue(writer.toString().contains(DeviceAuthorizationService.ERROR_EXPIRED_TOKEN));
    }

    @Test
    void pendingGrantAnswersAuthorizationPending() throws Exception {
        String grant = startDeviceFlow();
        String deviceCode = grant.split("\"device_code\":\"")[1].split("\"")[0];

        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        post("grant_type=" + url("urn:ietf:params:oauth:grant-type:device_code")
                + "&device_code=" + url(deviceCode));
        token.doPost(request, response);
        verify(response).setStatus(400);
        assertTrue(writer.toString().contains(DeviceAuthorizationService.ERROR_AUTHORIZATION_PENDING));
    }

    @Test
    void deniedGrantAnswersAccessDenied() throws Exception {
        String grant = startDeviceFlow();
        String deviceCode = grant.split("\"device_code\":\"")[1].split("\"")[0];
        String userCode = grant.split("\"user_code\":\"")[1].split("\"")[0];

        lenient().when(request.getParameter("user_code")).thenReturn(userCode);
        lenient().when(request.getParameter("username")).thenReturn("alice");
        lenient().when(request.getParameter("password")).thenReturn("wonderland");
        lenient().when(request.getParameter("decision")).thenReturn("deny");
        verification.doPost(request, response);
        assertTrue(writer.toString().contains("denied"));

        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        post("grant_type=" + url("urn:ietf:params:oauth:grant-type:device_code")
                + "&device_code=" + url(deviceCode));
        token.doPost(request, response);
        verify(response).setStatus(400);
        assertTrue(writer.toString().contains(DeviceAuthorizationService.ERROR_ACCESS_DENIED));
    }

    @Test
    void badCredentialsCannotApproveDevices() throws Exception {
        String grant = startDeviceFlow();
        String userCode = grant.split("\"user_code\":\"")[1].split("\"")[0];
        lenient().when(request.getParameter("user_code")).thenReturn(userCode);
        lenient().when(request.getParameter("username")).thenReturn("alice");
        lenient().when(request.getParameter("password")).thenReturn("wrong");
        lenient().when(request.getParameter("decision")).thenReturn("approve");
        verification.doPost(request, response);
        assertTrue(writer.toString().contains("Invalid credentials"));
    }

    @Test
    void userCodesUseUnconfusableAlphabet() throws Exception {
        String grant = startDeviceFlow();
        String userCode = grant.split("\"user_code\":\"")[1].split("\"")[0];
        assertTrue(userCode.matches("[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}"),
                "user code must avoid 0/O and 1/I: " + userCode);
    }

    @Test
    void deviceAuthorizationRejectsAnUnregisteredScope() throws Exception {
        writer.getBuffer().setLength(0);
        post("scope=admin");
        deviceAuthorization.doPost(request, response);
        verify(response).setStatus(400);
    }

    @Test
    void discoveryAdvertisesDeviceFlow() throws Exception {
        org.mockito.Mockito.clearInvocations(response);
        writer.getBuffer().setLength(0);
        new DiscoveryServlet(ISSUER, "").doGet(request, response);
        assertTrue(writer.toString().contains("device_authorization_endpoint"));
        assertTrue(writer.toString().contains("urn:ietf:params:oauth:grant-type:device_code"));
    }

    private static void assertEqualsSafe(Object expected, Object actual) {
        assertTrue(String.valueOf(expected).equals(String.valueOf(actual)),
                expected + " != " + actual);
    }

    private static jakarta.servlet.ServletInputStream inputStream(String content) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return new jakarta.servlet.ServletInputStream() {
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
        };
    }
}
