package org.picketlink.auth.oauth.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.picketlink.auth.oauth.ClientCredentialsAuthServer;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.service.ClientCredentialsTokenService;

@ExtendWith(MockitoExtension.class)
class OAuthTokenEndpointServletTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private ClientCredentialsTokenService tokenService;
    private StringWriter responseWriter;

    @BeforeEach
    void setUp() throws Exception {
        ClientCredentialsAuthServer authServer = ClientCredentialsAuthServer.builder(
                        "https://auth.example",
                        "https://auth.example/oauth/token")
                .build();
        authServer.getClientRegistry().register(RegisteredClient.builder("demo", "secret")
                .scope("api.read")
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                .build());
        tokenService = authServer.getTokenService();
        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    @Test
    void returnsAccessTokenForValidPost() throws Exception {
        when(request.getContentType()).thenReturn(OAuthConstants.APPLICATION_FORM_URLENCODED);
        when(request.getInputStream()).thenReturn(inputStream(
                "grant_type=client_credentials&client_id=demo&client_secret=secret&scope=api.read"));

        OAuthTokenEndpointServlet servlet = new OAuthTokenEndpointServlet(tokenService);
        servlet.doPost(request, response);

        ArgumentCaptor<Integer> statusCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(response).setStatus(statusCaptor.capture());
        verify(response).setContentType(eq(OAuthConstants.APPLICATION_JSON));
        assertEquals(HttpServletResponse.SC_OK, statusCaptor.getValue());
        assertTrue(responseWriter.toString().contains("\"access_token\""));
        assertTrue(responseWriter.toString().contains("\"token_type\":\"Bearer\""));
    }

    @Test
    void rejectsNonFormContentType() throws Exception {
        when(request.getContentType()).thenReturn("application/json");

        OAuthTokenEndpointServlet servlet = new OAuthTokenEndpointServlet(tokenService);
        servlet.doPost(request, response);

        ArgumentCaptor<Integer> statusCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(response).setStatus(statusCaptor.capture());
        assertEquals(HttpServletResponse.SC_BAD_REQUEST, statusCaptor.getValue());
        assertTrue(responseWriter.toString().contains("\"error\":\"invalid_request\""));
    }

    private static ServletInputStream inputStream(String body) {
        byte[] bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return new ServletInputStream() {
            private int index;

            @Override
            public int read() {
                if (index >= bytes.length) {
                    return -1;
                }
                return bytes[index++] & 0xff;
            }

            @Override
            public boolean isFinished() {
                return index >= bytes.length;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
            }
        };
    }
}
