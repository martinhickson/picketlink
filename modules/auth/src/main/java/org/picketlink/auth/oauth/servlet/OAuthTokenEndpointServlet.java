package org.picketlink.auth.oauth.servlet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.http.FormParameters;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.service.ClientCredentialsTokenService;

public class OAuthTokenEndpointServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient ClientCredentialsTokenService tokenService;

    public OAuthTokenEndpointServlet() {
    }

    public OAuthTokenEndpointServlet(ClientCredentialsTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void init() {
        if (tokenService == null) {
            Object configured = getServletContext().getAttribute(ClientCredentialsTokenService.class.getName());
            if (configured instanceof ClientCredentialsTokenService) {
                tokenService = (ClientCredentialsTokenService) configured;
            }
        }
        if (tokenService == null) {
            throw new IllegalStateException("ClientCredentialsTokenService must be configured");
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!isFormUrlEncoded(request)) {
            writeError(response, HttpServletResponse.SC_BAD_REQUEST,
                    new OAuthException(
                            new org.picketlink.auth.oauth.model.OAuthErrorResponse(
                                    OAuthConstants.INVALID_REQUEST,
                                    "Content-Type must be application/x-www-form-urlencoded"),
                            400));
            return;
        }

        String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> formParameters = FormParameters.parse(body);
        TokenRequest tokenRequest = TokenRequest.builder()
                .grantType(formParameters.get(OAuthConstants.GRANT_TYPE))
                .scope(formParameters.get(OAuthConstants.SCOPE))
                .authorizationHeader(request.getHeader("Authorization"))
                .formParameters(formParameters)
                .build();

        try {
            TokenResponse tokenResponse = tokenService.issueToken(tokenRequest);
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(OAuthConstants.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("Pragma", "no-cache");
            response.getWriter().write(OAuthJsonWriter.writeTokenResponse(tokenResponse));
        } catch (OAuthException ex) {
            writeError(response, ex.getHttpStatus(), ex);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        response.setHeader("Allow", "POST");
    }

    private static boolean isFormUrlEncoded(HttpServletRequest request) {
        String contentType = request.getContentType();
        if (contentType == null) {
            return false;
        }
        return contentType.toLowerCase().startsWith(OAuthConstants.APPLICATION_FORM_URLENCODED);
    }

    private static void writeError(HttpServletResponse response, int status, OAuthException ex)
            throws IOException {
        response.setStatus(status);
        response.setContentType(OAuthConstants.APPLICATION_JSON);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(OAuthJsonWriter.writeErrorResponse(ex.getError()));
    }
}
