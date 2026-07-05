package org.picketlink.idm.admin.servlet;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.picketlink.idm.admin.standalone.StandaloneConfigurationResult;
import org.picketlink.idm.admin.standalone.StandaloneConfigurationService;
import org.picketlink.idm.admin.standalone.WildFlyConfigurationProfile;

public class StandaloneConfigServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient StandaloneConfigurationService configurationService;

    public StandaloneConfigServlet() {
    }

    public StandaloneConfigServlet(StandaloneConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @Override
    public void init() {
        if (configurationService == null) {
            configurationService = new StandaloneConfigurationService();
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        response.getWriter().write(IdmAdminJsonWriter.writeProfiles());
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        String profileId = request.getParameter("profile");
        String jbossHome = request.getParameter("jbossHome");
        boolean removeHttps = "true".equalsIgnoreCase(request.getParameter("removeHttpsListener"));
        if (profileId == null || profileId.isBlank() || jbossHome == null || jbossHome.isBlank()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmAdminJsonWriter.writeError("profile and jbossHome are required"));
            return;
        }
        try {
            WildFlyConfigurationProfile profile = WildFlyConfigurationProfile.fromId(profileId.trim());
            StandaloneConfigurationResult result = configurationService.applyProfile(
                    Path.of(jbossHome.trim()), profile, removeHttps);
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write(IdmAdminJsonWriter.writeResult(result));
        } catch (IllegalArgumentException ex) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmAdminJsonWriter.writeError("Unknown profile: " + profileId));
        } catch (Exception ex) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write(IdmAdminJsonWriter.writeError(ex.getMessage()));
        }
    }
}
