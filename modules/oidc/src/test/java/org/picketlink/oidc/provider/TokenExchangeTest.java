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
 * PL-115: Token Exchange (RFC 8693) — the microservice delegation pattern: a downstream
 * service exchanges an incoming subject token for one scoped to its audience, with the
 * delegation chain (act) auditable end to end.
 */
@ExtendWith(MockitoExtension.class)
class TokenExchangeTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String GATEWAY_ID = "api-gateway";
    private static final String GATEWAY_SECRET = "gateway-secret";
    private static final String SERVICE_ID = "billing-service";
    private static final String SERVICE_SECRET = "service-secret";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OidcProviderServer server;
    private OidcTokenEndpointServlet token;
    private StringWriter writer;

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                java.nio.file.Files.createTempDirectory("plk-tx").resolve("k.p12").toString());
        ManagedIssuanceServer issuanceServer = ManagedIssuanceServer.builder(ISSUER).build();
        issuanceServer.getClientStore().save(RegisteredClient.builder(GATEWAY_ID, GATEWAY_SECRET)
                .scope("read")
                .build());
        issuanceServer.getClientStore().save(RegisteredClient.builder(SERVICE_ID, SERVICE_SECRET)
                .scope("read")
                .build());
        server = OidcProviderServer.builder(ISSUER, issuanceServer).build();
        token = new OidcTokenEndpointServlet(server);
        writer = new StringWriter();
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(writer));
    }

    private void post(String formBody, String clientId, String clientSecret) throws Exception {
        lenient().when(request.getInputStream()).thenReturn(inputStream(formBody));
        lenient().when(request.getHeader("Authorization")).thenReturn("Basic "
                + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()));
        token.doPost(request, response);
    }

    private static String url(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Issues a subject token as the gateway would have received it (user context). */
    private String subjectTokenForAlice() throws Exception {
        org.mockito.Mockito.clearInvocations(response);
        writer.getBuffer().setLength(0);
        post("grant_type=client_credentials&scope=read", GATEWAY_ID, GATEWAY_SECRET);
        verify(response).setStatus(200);
        return writer.toString().split("\"access_token\":\"")[1].split("\"")[0];
    }

    @Test
    void exchangesSubjectTokenForDownstreamAudience() throws Exception {
        String subjectToken = subjectTokenForAlice();

        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        post("grant_type=" + url("urn:ietf:params:oauth:grant-type:token-exchange")
                + "&subject_token=" + url(subjectToken)
                + "&subject_token_type=" + url("urn:ietf:params:oauth:token-type:jwt")
                + "&audience=" + url("https://billing.corp.example"),
                SERVICE_ID, SERVICE_SECRET);
        verify(response).setStatus(200);
        String json = writer.toString();
        assertTrue(json.contains("\"issued_token_type\":\"urn:ietf:params:oauth:token-type:jwt\""));

        String exchanged = json.split("\"access_token\":\"")[1].split("\"")[0];
        String payload = new String(Base64.getUrlDecoder().decode(exchanged.split("\\.")[1]),
                StandardCharsets.UTF_8);
        // the subject context carries over and the audience is the downstream service
        assertTrue(payload.contains("https://billing.corp.example"), "audience must be set");
        assertNotNull(server.getIssuanceServer().getIssuanceManager().validate(exchanged),
                "exchanged token must validate through the chokepoint");
    }

    @Test
    void delegationChainIsRecordedViaActClaim() throws Exception {
        String subjectToken = subjectTokenForAlice();
        // the gateway first exchanges for its own downstream token (actor)...
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        post("grant_type=" + url("urn:ietf:params:oauth:grant-type:token-exchange")
                + "&subject_token=" + url(subjectToken)
                + "&subject_token_type=" + url("urn:ietf:params:oauth:token-type:jwt"),
                GATEWAY_ID, GATEWAY_SECRET);
        verify(response).setStatus(200);
        String actorToken = writer.toString().split("\"access_token\":\"")[1].split("\"")[0];

        // ...then the billing service exchanges the subject token naming the gateway as actor:
        // the original user context survives and act records who delegated
        writer.getBuffer().setLength(0);
        org.mockito.Mockito.clearInvocations(response);
        post("grant_type=" + url("urn:ietf:params:oauth:grant-type:token-exchange")
                + "&subject_token=" + url(subjectToken)
                + "&subject_token_type=" + url("urn:ietf:params:oauth:token-type:jwt")
                + "&actor_token=" + url(actorToken)
                + "&actor_token_type=" + url("urn:ietf:params:oauth:token-type:jwt"),
                SERVICE_ID, SERVICE_SECRET);
        verify(response).setStatus(200);
        String delegated = writer.toString().split("\"access_token\":\"")[1].split("\"")[0];
        String payload = new String(Base64.getUrlDecoder().decode(delegated.split("\\.")[1]),
                StandardCharsets.UTF_8);
        assertTrue(payload.contains("\"act\""), "delegation must be recorded");
        assertTrue(payload.contains("\"sub\":\"" + GATEWAY_ID + "\"")
                        || payload.contains("\"sub\\\":\\\"" + GATEWAY_ID),
                "act.sub must name the delegating gateway");
    }

    @Test
    void invalidSubjectTokenIsRejected() throws Exception {
        org.mockito.Mockito.clearInvocations(response);
        post("grant_type=" + url("urn:ietf:params:oauth:grant-type:token-exchange")
                + "&subject_token=not-a-jwt"
                + "&subject_token_type=" + url("urn:ietf:params:oauth:token-type:jwt"),
                SERVICE_ID, SERVICE_SECRET);
        verify(response).setStatus(400);
        assertTrue(writer.toString().contains("subject_token"));
    }

    @Test
    void missingSubjectTokenIsRejected() throws Exception {
        org.mockito.Mockito.clearInvocations(response);
        post("grant_type=" + url("urn:ietf:params:oauth:grant-type:token-exchange"),
                SERVICE_ID, SERVICE_SECRET);
        verify(response).setStatus(400);
    }

    @Test
    void discoveryAdvertisesTokenExchange() throws Exception {
        org.mockito.Mockito.clearInvocations(response);
        writer.getBuffer().setLength(0);
        new DiscoveryServlet(ISSUER, "").doGet(request, response);
        assertTrue(writer.toString().contains("urn:ietf:params:oauth:grant-type:token-exchange"));
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
