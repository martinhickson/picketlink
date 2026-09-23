package org.picketlink.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.List;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.apache.cxf.rs.security.oauth2.grants.code.AuthorizationCodeGrantHandler;
import org.apache.cxf.rs.security.oauth2.grants.code.CodeVerifierTransformer;
import org.apache.cxf.rs.security.oauth2.provider.AccessTokenGrantHandler;
import org.junit.jupiter.api.Test;
import org.picketlink.oidc.provider.AuthorizationCodeService;

/** The CXF authorization-code grant mounted by the demo requires S256 PKCE. */
class OidcCodeGrantPkceTest {

    @Test
    void authorizeRejectsAMissingChallenge() {
        DemoOidcAuthorizationCodeService service = new DemoOidcAuthorizationCodeService();
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.add("response_type", "code");
        params.add("client_id", "seam-booking");
        try (Response response = service.startAuthorization(params)) {
            assertEquals(400, response.getStatus());
            assertTrue(response.getEntity().toString().contains("PKCE S256 is required"));
        }
    }

    @Test
    void grantHandlerRequiresS256AndRejectsAShortVerifier() throws Exception {
        OidcAuthorizationServerConfig config = OidcAuthorizationServerConfig.builder("https://issuer.example")
                .client(OidcClientRegistration.builder("seam-booking", "seam-booking-secret")
                        .redirectUri("http://127.0.0.11:8080/seam-booking/oidc/callback")
                        .scope("openid")
                        .grantType("authorization_code")
                        .build())
                .build();
        List<AccessTokenGrantHandler> handlers =
                OidcAuthorizationServerBootstrap.grantHandlers(null, config);
        AuthorizationCodeGrantHandler handler = (AuthorizationCodeGrantHandler) handlers.get(0);

        assertTrue(field(handler, "requireCodeVerifier"));
        @SuppressWarnings("unchecked")
        List<CodeVerifierTransformer> transformers =
                (List<CodeVerifierTransformer>) fieldValue(handler, "codeVerifierTransformers");
        CodeVerifierTransformer fallback =
                (CodeVerifierTransformer) fieldValue(handler, "defaultCodeVerifierTransformer");
        assertEquals(1, transformers.size());
        assertEquals("S256", transformers.get(0).getChallengeMethod());
        assertEquals("S256", fallback.getChallengeMethod());

        String verifier = "a".repeat(43);
        assertEquals(AuthorizationCodeService.s256(verifier),
                transformers.get(0).transformCodeVerifier(verifier));
        assertEquals("", transformers.get(0).transformCodeVerifier("short"));
        assertEquals("", transformers.get(0).transformCodeVerifier("a".repeat(129)));
    }

    private static boolean field(Object target, String name) throws Exception {
        return (Boolean) fieldValue(target, name);
    }

    private static Object fieldValue(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }
}
