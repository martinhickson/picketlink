package org.picketlink.auth.oauth.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.InMemoryClientRegistry;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.model.TokenRequest;

class ClientCredentialsAuthenticatorTest {

    private InMemoryClientRegistry registry;
    private ClientCredentialsAuthenticator authenticator;

    @BeforeEach
    void setUp() {
        registry = new InMemoryClientRegistry();
        registry.register(RegisteredClient.builder("service-a", "s3cr3t")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build());
        registry.register(RegisteredClient.builder("service-b", "post-secret")
                .scope("api.write")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                .build());
        authenticator = new ClientCredentialsAuthenticator(registry, new ConstantTimeClientSecretMatcher());
    }

    @Test
    void authenticatesClientSecretBasic() {
        String basic = "Basic "
                + Base64.getEncoder().encodeToString("service-a:s3cr3t".getBytes(StandardCharsets.UTF_8));
        TokenRequest request = TokenRequest.builder()
                .authorizationHeader(basic)
                .build();

        ClientAuthentication authentication = authenticator.authenticate(request);

        assertEquals("service-a", authentication.getClient().getClientId());
        assertEquals(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC, authentication.getAuthMethod());
    }

    @Test
    void authenticatesClientSecretPost() {
        TokenRequest request = TokenRequest.builder()
                .formParameter(OAuthConstants.CLIENT_ID, "service-b")
                .formParameter(OAuthConstants.CLIENT_SECRET, "post-secret")
                .build();

        ClientAuthentication authentication = authenticator.authenticate(request);

        assertEquals("service-b", authentication.getClient().getClientId());
        assertEquals(TokenEndpointAuthMethod.CLIENT_SECRET_POST, authentication.getAuthMethod());
    }

    @Test
    void rejectsInvalidSecret() {
        TokenRequest request = TokenRequest.builder()
                .formParameter(OAuthConstants.CLIENT_ID, "service-b")
                .formParameter(OAuthConstants.CLIENT_SECRET, "wrong")
                .build();

        OAuthException ex = assertThrows(OAuthException.class, () -> authenticator.authenticate(request));
        assertEquals(OAuthConstants.INVALID_CLIENT, ex.getError().getError());
        assertEquals(401, ex.getHttpStatus());
    }

    @Test
    void rejectsAuthMethodMismatch() {
        TokenRequest request = TokenRequest.builder()
                .formParameter(OAuthConstants.CLIENT_ID, "service-a")
                .formParameter(OAuthConstants.CLIENT_SECRET, "s3cr3t")
                .build();

        OAuthException ex = assertThrows(OAuthException.class, () -> authenticator.authenticate(request));
        assertEquals(OAuthConstants.INVALID_CLIENT, ex.getError().getError());
    }
}
