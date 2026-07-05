package org.picketlink.idm.admin.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.picketlink.idm.realm.IdmRealmProviderConfig;
import org.picketlink.idm.realm.config.IdmRealmConfigService;
import org.picketlink.idm.realm.config.IdmRealmConfigStores;
import org.picketlink.idm.realm.config.JsonFileIdmRealmConfigStore;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IdmRealmConfigServletTest {

    @TempDir
    Path tempDir;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private StringWriter responseWriter;
    private IdmRealmConfigServlet servlet;

    @BeforeEach
    void setUp() throws Exception {
        System.setProperty("picketlink.idm.realm.config.file", tempDir.resolve("picketlink-realm-config.json").toString());
        IdmRealmConfigStores.resetForTests();
        servlet = new IdmRealmConfigServlet(new IdmRealmConfigService(
                new JsonFileIdmRealmConfigStore(tempDir.resolve("picketlink-realm-config.json"))));
        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    @AfterEach
    void tearDown() {
        System.clearProperty("picketlink.idm.realm.config.file");
        IdmRealmConfigStores.resetForTests();
    }

    @Test
    void getReturnsDefaultDocumentProvider() throws Exception {
        servlet.doGet(request, response);
        assertTrue(responseWriter.toString().contains("\"provider\":\"document\""));
        assertTrue(responseWriter.toString().contains("defaultScimBaseUrl"));
    }

    @Test
    void postSavesScimProviderSettings() throws Exception {
        when(request.getParameter("provider")).thenReturn(IdmRealmProviderConfig.PROVIDER_SCIM);
        when(request.getParameter("scimBaseUrl")).thenReturn("http://127.0.0.1:9999/scim");
        when(request.getParameter("useDefaultBaseUrl")).thenReturn("false");
        when(request.getParameter("syncToDocument")).thenReturn("false");

        servlet.doPost(request, response);

        ArgumentCaptor<Integer> statusCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(response).setStatus(statusCaptor.capture());
        assertEquals(HttpServletResponse.SC_OK, statusCaptor.getValue());
        assertTrue(responseWriter.toString().contains("\"provider\":\"scim\""));
        assertTrue(responseWriter.toString().contains("http://127.0.0.1:9999/scim"));
    }
}
