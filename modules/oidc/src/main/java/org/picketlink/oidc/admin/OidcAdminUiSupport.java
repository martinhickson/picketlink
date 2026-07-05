package org.picketlink.oidc.admin;

/**
 * Deployment constants for the OIDC admin Angular UI served by
 * {@code org.picketlink.auth.oauth.servlet.VirtualResourcesServlet}.
 */
public final class OidcAdminUiSupport {

    public static final String RESOURCE_BASE = "META-INF/resources/oidc-admin-ui";
    public static final String DEFAULT_URL_BASE = "/app";
    public static final String VIRTUAL_RESOURCES_SERVLET =
            "org.picketlink.auth.oauth.servlet.VirtualResourcesServlet";
    public static final String INIT_PARAM_RESOURCE_BASE = "resourceBase";
    public static final String INIT_PARAM_URL_BASE = "urlBase";
    public static final String INIT_PARAM_ADMIN_UI_ENABLED = "adminUiEnabled";
    public static final String ADMIN_UI_ENABLED_VALUE = "true";

    private OidcAdminUiSupport() {
    }
}
