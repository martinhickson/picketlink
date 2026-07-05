package org.picketlink.oidc;

import java.util.Collections;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.rs.security.jose.jaxrs.JsonWebKeysProvider;
import org.apache.cxf.rs.security.oauth2.client.ClientTokenContextProvider;
import org.apache.cxf.rs.security.oauth2.client.Consumer;
import org.apache.cxf.rs.security.oauth2.client.MemoryClientCodeStateManager;
import org.apache.cxf.rs.security.oauth2.client.MemoryClientTokenContextManager;
import org.apache.cxf.rs.security.oidc.rp.IdTokenContextClassProvider;
import org.apache.cxf.rs.security.oidc.rp.IdTokenReader;

public final class OidcRelyingPartyBootstrap {

    private OidcRelyingPartyBootstrap() {
    }

    public static OidcPathScopedClientCodeRequestFilter createAuthFilter(String authorizationServiceUri,
            String tokenServiceUri,
            String completeUri,
            String startUri) {
        return createAuthFilter(authorizationServiceUri, tokenServiceUri, completeUri, completeUri, startUri, null, null);
    }

    public static OidcPathScopedClientCodeRequestFilter createAuthFilter(String authorizationServiceUri,
            String tokenServiceUri,
            String redirectUri,
            String completePath,
            String startUri,
            String issuer,
            String jwksUri) {
        return createSetup(authorizationServiceUri, tokenServiceUri, redirectUri, completePath, startUri, issuer,
                jwksUri).authFilter();
    }

    public static RelyingPartySetup createSetup(String authorizationServiceUri,
            String tokenServiceUri,
            String redirectUri,
            String completePath,
            String startUri,
            String issuer,
            String jwksUri) {
        Consumer consumer = new Consumer(OidcDemoConstants.CLIENT_ID, OidcDemoConstants.CLIENT_SECRET);

        WebClient tokenClient = WebClient.create(tokenServiceUri);
        tokenClient.header("Accept", "application/json");

        MemoryClientCodeStateManager codeStateManager = new MemoryClientCodeStateManager();
        MemoryClientTokenContextManager tokenContextManager = new MemoryClientTokenContextManager();

        OidcPathScopedClientCodeRequestFilter authFilter = new OidcPathScopedClientCodeRequestFilter();
        authFilter.setConsumer(consumer);
        authFilter.setAuthorizationServiceUri(authorizationServiceUri);
        authFilter.setAccessTokenServiceClient(tokenClient);
        authFilter.setRedirectUri(redirectUri);
        if (completePath != null) {
            authFilter.setCompleteUri(completePath);
        }
        authFilter.setStartUri(startUri);
        authFilter.setScopes(String.join(" ", OidcDemoConstants.DEFAULT_SCOPES));
        authFilter.setBlockAccessDeniedResponses(true);
        authFilter.setClientCodeStateManager(codeStateManager);
        authFilter.setClientTokenContextManager(tokenContextManager);

        if (issuer != null && jwksUri != null) {
            IdTokenReader idTokenReader = new IdTokenReader();
            WebClient jwksClient = WebClient.create(jwksUri, Collections.singletonList(new JsonWebKeysProvider()));
            idTokenReader.setJwkSetClient(jwksClient);
            idTokenReader.setIssuerId(issuer);
            authFilter.setIdTokenReader(idTokenReader);
        }

        return new RelyingPartySetup(authFilter, tokenContextManager);
    }

    public record RelyingPartySetup(
            OidcPathScopedClientCodeRequestFilter authFilter,
            MemoryClientTokenContextManager tokenContextManager) {
    }

    public static Object[] defaultProviders(OidcPathScopedClientCodeRequestFilter authFilter) {
        return new Object[] {
                authFilter,
                new IdTokenContextClassProvider(),
                new ClientTokenContextProvider()
        };
    }
}
