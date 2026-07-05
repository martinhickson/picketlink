package org.picketlink.idm.admin.servlet;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.picketlink.idm.realm.IdmRealmProviderConfig;
import org.picketlink.idm.realm.config.IdmRealmConfigDocument;
import org.picketlink.idm.realm.config.IdmRealmConfigService;
import org.picketlink.idm.realm.config.IdmRealmConfigSnapshot;

public class IdmRealmConfigServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient IdmRealmConfigService configService;

    public IdmRealmConfigServlet() {
    }

    public IdmRealmConfigServlet(IdmRealmConfigService configService) {
        this.configService = configService;
    }

    @Override
    public void init() {
        if (configService == null) {
            configService = IdmRealmConfigService.global();
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        IdmRealmConfigSnapshot snapshot = configService.loadSnapshot();
        response.getWriter().write(IdmRealmConfigJsonWriter.writeSnapshot(snapshot));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        String provider = request.getParameter("provider");
        if (provider == null || provider.isBlank()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmRealmConfigJsonWriter.writeError("provider is required"));
            return;
        }
        try {
            IdmRealmConfigDocument document = new IdmRealmConfigDocument(
                    provider.trim(),
                    valueOrEmpty(request.getParameter("scimBaseUrl")),
                    parseBoolean(request.getParameter("useDefaultBaseUrl"), true),
                    valueOrEmpty(request.getParameter("scimContextPath")),
                    valueOrEmpty(request.getParameter("bearerToken")),
                    parseBoolean(request.getParameter("syncToDocument"), true),
                    valueOrEmpty(request.getParameter("usersPath")),
                    valueOrEmpty(request.getParameter("groupsPath")),
                    valueOrEmpty(request.getParameter("rolesPath")));
            if (IdmRealmProviderConfig.PROVIDER_SCIM.equals(document.getProvider())
                    && !document.isUseDefaultBaseUrl()
                    && document.getScimBaseUrl().isBlank()) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write(IdmRealmConfigJsonWriter.writeError(
                        "scimBaseUrl is required when useDefaultBaseUrl=false"));
                return;
            }
            IdmRealmConfigSnapshot saved = configService.save(document);
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write(IdmRealmConfigJsonWriter.writeSnapshot(saved));
        } catch (IllegalArgumentException ex) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmRealmConfigJsonWriter.writeError(ex.getMessage()));
        }
    }

    private static String valueOrEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    private static boolean parseBoolean(String value, boolean defaultValue) {
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return !"false".equalsIgnoreCase(value.trim());
    }
}
