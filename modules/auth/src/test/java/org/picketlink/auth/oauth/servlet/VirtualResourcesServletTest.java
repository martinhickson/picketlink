package org.picketlink.auth.oauth.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class VirtualResourcesServletTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private ServletConfig servletConfig;

    private VirtualResourcesServlet servlet;

    @BeforeEach
    void setUp() {
        servlet = new VirtualResourcesServlet();
    }

    @Test
    void resolvesRelativePathFromConfiguredUrlBase() {
        when(request.getRequestURI()).thenReturn("/myapp/auth-ui/main-ABC.js");
        when(request.getContextPath()).thenReturn("/myapp");

        assertEquals("main-ABC.js", servlet.resolveRelativePath(request));
    }

    @Test
    void normalizesCustomUrlBase() {
        assertEquals("/admin/clients", VirtualResourcesServlet.normalizeUrlBase("/admin/clients/"));
    }

    @Test
    void adminUiEnabledRequiresTrueInitParam() {
        assertFalse(VirtualResourcesServlet.isAdminUiEnabled(null));
        assertFalse(VirtualResourcesServlet.isAdminUiEnabled(""));
        assertFalse(VirtualResourcesServlet.isAdminUiEnabled("false"));
        assertTrue(VirtualResourcesServlet.isAdminUiEnabled("true"));
        assertTrue(VirtualResourcesServlet.isAdminUiEnabled(" TRUE "));
    }

    @Test
    void rejectsRequestsWhenAdminUiDisabled() throws Exception {
        when(servletConfig.getInitParameter(anyString())).thenReturn(null);
        servlet.init(servletConfig);
        servlet.doGet(request, response);
        verify(response).sendError(
                HttpServletResponse.SC_FORBIDDEN,
                VirtualResourcesServlet.PERMISSION_DENIED_MESSAGE);
    }
}
