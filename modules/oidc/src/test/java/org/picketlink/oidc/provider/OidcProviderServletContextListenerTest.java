package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
        for (String path : new String[] {
                "/authorize", "/par", "/device_authorization", "/device", "/token",
                "/userinfo", "/logout", "/introspect", "/revoke", "/jwks.json",
                "/.well-known/openid-configuration" }) {
            assertTrue(fragment.contains("<url-pattern>" + path + "</url-pattern>"), path);
        }
        assertTrue(fragment.contains("oidc-revoke"));
        assertTrue(fragment.contains("OidcProviderServletContextListener"));
    }
}
