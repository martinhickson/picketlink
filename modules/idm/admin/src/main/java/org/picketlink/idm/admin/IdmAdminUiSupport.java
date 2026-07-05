package org.picketlink.idm.admin;

public final class IdmAdminUiSupport {

    public static final String RESOURCE_BASE = "META-INF/resources/idm-admin-ui";
    public static final String DEFAULT_URL_BASE = "/idm-admin";
    public static final String VIRTUAL_RESOURCES_SERVLET =
            "org.picketlink.auth.oauth.servlet.VirtualResourcesServlet";
    public static final String INIT_PARAM_RESOURCE_BASE = "resourceBase";
    public static final String INIT_PARAM_URL_BASE = "urlBase";
    public static final String INIT_PARAM_ADMIN_UI_ENABLED = "adminUiEnabled";
    public static final String ADMIN_UI_ENABLED_VALUE = "true";

    private IdmAdminUiSupport() {
    }
}
