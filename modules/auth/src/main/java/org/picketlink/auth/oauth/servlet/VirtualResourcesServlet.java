package org.picketlink.auth.oauth.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.logging.Logger;

/**
 * Serves static resources from the classpath, typically Angular assets packaged under
 * {@code META-INF/resources/auth-ui}. The URL base is configurable so the UI can be
 * mounted at {@code /auth-ui}, {@code /admin/clients}, etc.
 */
public class VirtualResourcesServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG = Logger.getLogger(VirtualResourcesServlet.class);

    public static final String INIT_PARAM_RESOURCE_BASE = "resourceBase";
    public static final String INIT_PARAM_URL_BASE = "urlBase";
    public static final String INIT_PARAM_ADMIN_UI_ENABLED = "adminUiEnabled";
    public static final String ADMIN_UI_ENABLED_VALUE = "true";
    public static final String PERMISSION_DENIED_MESSAGE = "Permission denied";
    public static final String DEFAULT_RESOURCE_BASE = "META-INF/resources/auth-ui";
    public static final String DEFAULT_URL_BASE = "/auth-ui";

    private String resourceBase = DEFAULT_RESOURCE_BASE;
    private String urlBase = DEFAULT_URL_BASE;
    private boolean adminUiEnabled;

    @Override
    public void init() {
        String configuredResourceBase = getInitParameter(INIT_PARAM_RESOURCE_BASE);
        if (configuredResourceBase != null && !configuredResourceBase.isBlank()) {
            resourceBase = trimSlashes(configuredResourceBase);
        }
        String configuredUrlBase = getInitParameter(INIT_PARAM_URL_BASE);
        if (configuredUrlBase != null && !configuredUrlBase.isBlank()) {
            urlBase = normalizeUrlBase(configuredUrlBase);
        }
        adminUiEnabled = isAdminUiEnabled(getInitParameter(INIT_PARAM_ADMIN_UI_ENABLED));
        if (!adminUiEnabled) {
            LOG.warnf(
                    "Angular admin UI is disabled. Add servlet init-param %s=%s to the "
                            + "VirtualResourcesServlet definition in web.xml to enable the auth UI.",
                    INIT_PARAM_ADMIN_UI_ENABLED,
                    ADMIN_UI_ENABLED_VALUE);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!adminUiEnabled) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, PERMISSION_DENIED_MESSAGE);
            return;
        }
        String relativePath = resolveRelativePath(request);
        if (relativePath.endsWith("/")) {
            relativePath = relativePath + "index.html";
        }
        if (!serveResource(relativePath, response)) {
            if (serveResource("index.html", response)) {
                return;
            }
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    String resolveRelativePath(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String servletPath = requestUri.substring(contextPath.length());
        if (servletPath.startsWith(urlBase)) {
            servletPath = servletPath.substring(urlBase.length());
        }
        if (servletPath.isEmpty()) {
            return "index.html";
        }
        if (servletPath.startsWith("/")) {
            servletPath = servletPath.substring(1);
        }
        return servletPath;
    }

    private boolean serveResource(String relativePath, HttpServletResponse response) throws IOException {
        String resourcePath = resourceBase + "/" + relativePath;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = VirtualResourcesServlet.class.getClassLoader();
        }
        URL resource = classLoader.getResource(resourcePath);
        if (resource == null) {
            return false;
        }
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(guessContentType(relativePath));
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        try (InputStream input = resource.openStream(); OutputStream output = response.getOutputStream()) {
            input.transferTo(output);
        }
        return true;
    }

    static String guessContentType(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".html")) {
            return "text/html";
        }
        if (lower.endsWith(".js")) {
            return "application/javascript";
        }
        if (lower.endsWith(".css")) {
            return "text/css";
        }
        if (lower.endsWith(".json")) {
            return "application/json";
        }
        if (lower.endsWith(".svg")) {
            return "image/svg+xml";
        }
        if (lower.endsWith(".png")) {
            return "image/png";
        }
        if (lower.endsWith(".ico")) {
            return "image/x-icon";
        }
        if (lower.endsWith(".woff2")) {
            return "font/woff2";
        }
        return "application/octet-stream";
    }

    static String normalizeUrlBase(String value) {
        String normalized = value.trim();
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        if (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    static String trimSlashes(String value) {
        String trimmed = value.trim();
        while (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    static boolean isAdminUiEnabled(String configuredValue) {
        return configuredValue != null
                && ADMIN_UI_ENABLED_VALUE.equalsIgnoreCase(configuredValue.trim());
    }
}
