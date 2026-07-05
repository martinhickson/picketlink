package org.picketlink.auth.oauth.servlet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.admin.ClientRegistrationException;
import org.picketlink.auth.oauth.admin.ClientRegistrationJsonWriter;
import org.picketlink.auth.oauth.admin.ClientRegistrationRequest;
import org.picketlink.auth.oauth.admin.ClientRegistrationService;
import org.picketlink.auth.oauth.admin.ClientRegistrationView;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;

public class ClientRegistrationServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient ClientRegistrationService registrationService;

    public ClientRegistrationServlet() {
    }

    public ClientRegistrationServlet(ClientRegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @Override
    public void init() {
        if (registrationService == null) {
            Object configured = getServletContext().getAttribute(ClientRegistrationService.class.getName());
            if (configured instanceof ClientRegistrationService) {
                registrationService = (ClientRegistrationService) configured;
            }
        }
        if (registrationService == null) {
            throw new IllegalStateException("ClientRegistrationService must be configured");
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK,
                ClientRegistrationJsonWriter.writeViews(registrationService.listClients()));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!isJson(request)) {
            writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Content-Type must be application/json");
            return;
        }
        String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        try {
            ClientRegistrationRequest registrationRequest = ClientRegistrationJsonWriter.readRequest(body);
            ClientRegistrationView created = registrationService.registerClient(registrationRequest);
            writeJson(response, HttpServletResponse.SC_CREATED, ClientRegistrationJsonWriter.writeView(created));
        } catch (ClientRegistrationException ex) {
            writeError(response, HttpServletResponse.SC_BAD_REQUEST, ex.getMessage());
        }
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String clientId = extractClientId(request.getPathInfo());
        if (clientId == null || clientId.isBlank()) {
            writeError(response, HttpServletResponse.SC_BAD_REQUEST, "clientId is required");
            return;
        }
        if (registrationService.deleteClient(clientId)) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        } else {
            writeError(response, HttpServletResponse.SC_NOT_FOUND, "Client not found");
        }
    }

    private static String extractClientId(String pathInfo) {
        if (pathInfo == null || pathInfo.length() <= 1) {
            return null;
        }
        return pathInfo.substring(1);
    }

    private static boolean isJson(HttpServletRequest request) {
        String contentType = request.getContentType();
        return contentType != null
                && contentType.toLowerCase().startsWith(OAuthConstants.APPLICATION_JSON);
    }

    private static void writeJson(HttpServletResponse response, int status, String json) throws IOException {
        response.setStatus(status);
        response.setContentType(OAuthConstants.APPLICATION_JSON);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(json);
    }

    private static void writeError(HttpServletResponse response, int status, String message) throws IOException {
        OAuthErrorResponse error = new OAuthErrorResponse(OAuthConstants.INVALID_REQUEST, message);
        String json = "{\"error\":\"" + error.getError() + "\",\"error_description\":\""
                + error.getErrorDescription() + "\"}";
        writeJson(response, status, json);
    }
}
