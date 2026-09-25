package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.admin.ManagedIssuanceServer;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;

@ExtendWith(MockitoExtension.class)
class OidcProviderServletContextListenerTest {

    @Mock
    private ServletContext servletContext;

    @Mock
    private ServletContextEvent event;

    @Test
    void webXmlSeedsTheClientAndTheDemoUsers() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                Files.createTempDirectory("plk-listener").resolve("k.p12").toString());
        Map<String, String> params = new HashMap<>();
        params.put("issuer", "https://auth.example.test");
        params.put("subjectAuthenticator", ConfiguredUsers.class.getName());
        params.put("users", "alice=wonderland,bob=secret");
        params.put("clientId", "rp");
        params.put("clientSecret", "rp-secret");
        params.put("tokenEndpointAuthMethod", "client_secret_post");
        params.put("scopes", "openid profile");
        params.put("redirectUris", "https://rp.example/cb");
        params.put("backchannelLogoutUrl", "https://rp.example/logout");
        when(event.getServletContext()).thenReturn(servletContext);
        lenient().when(servletContext.getServletRegistrations()).thenReturn(java.util.Map.of());
        lenient().when(servletContext.addServlet(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(org.mockito.Mockito.mock(jakarta.servlet.ServletRegistration.Dynamic.class));
        when(servletContext.getInitParameter(org.mockito.ArgumentMatchers.anyString()))
                .thenAnswer(invocation -> params.get(invocation.getArgument(0)));
        Map<String, Object> attributes = new HashMap<>();
        org.mockito.Mockito.doAnswer(invocation -> {
            attributes.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(servletContext).setAttribute(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any());

        new OidcProviderServletContextListener().contextInitialized(event);

        ManagedIssuanceServer issuance = (ManagedIssuanceServer) attributes.get(
                ManagedIssuanceServer.class.getName());
        RegisteredClient client = issuance.getClientStore().findByClientId("rp").get();
        assertEquals(TokenEndpointAuthMethod.CLIENT_SECRET_POST, client.getTokenEndpointAuthMethod());
        assertTrue(client.getAllowedRedirectUris().contains("https://rp.example/cb"));
        assertEquals("https://rp.example/logout", client.getBackchannelLogoutUrl());
        OidcProviderServer server = (OidcProviderServer) attributes.get(OidcProviderServer.class.getName());
        assertEquals("alice", server.getSubjectAuthenticator().authenticate("alice", "wonderland").get());
        assertTrue(server.getSubjectAuthenticator().authenticate("bob", "nope").isEmpty());
    }

    @Test
    void fragmentMountsTheAdvertisedEndpoints() throws Exception {
        String fragment = new String(OidcProviderServletContextListener.class.getResourceAsStream(
                "/META-INF/web-fragment.xml").readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(fragment.contains("OidcProviderServletContextListener"));
        assertFalse(fragment.contains("<servlet-mapping>"));
        assertFalse(fragment.contains("<url-pattern>"));
    }

    @Test
    void leavesAPatternTheWarAlreadyMapped() {
        System.setProperty("picketlink.auth.keystore.path",
                java.nio.file.Path.of(System.getProperty("java.io.tmpdir"), "plk-listener-skip.p12").toString());
        Map<String, String> params = new HashMap<>();
        params.put("issuer", "https://auth.example.test");
        jakarta.servlet.ServletRegistration existing = org.mockito.Mockito.mock(jakarta.servlet.ServletRegistration.class);
        when(existing.getMappings()).thenReturn(java.util.Set.of("/token"));
        when(event.getServletContext()).thenReturn(servletContext);
        org.mockito.Mockito.doReturn(java.util.Map.of("token", existing))
                .when(servletContext).getServletRegistrations();
        when(servletContext.getInitParameter(anyString())).thenAnswer(invocation -> params.get(invocation.getArgument(0)));
        when(servletContext.addServlet(anyString(), anyString()))
                .thenReturn(org.mockito.Mockito.mock(jakarta.servlet.ServletRegistration.Dynamic.class));
        org.mockito.Mockito.doNothing().when(servletContext).setAttribute(anyString(), org.mockito.ArgumentMatchers.any());

        new OidcProviderServletContextListener().contextInitialized(event);

        verify(servletContext, never()).addServlet(eq("oidc-token"), anyString());
        verify(servletContext).addServlet(eq("oidc-authorize"), anyString());
    }
}
