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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.picketlink.idm.document.IdmDocumentStores;
import org.picketlink.idm.document.IdmRealmService;
import org.picketlink.idm.document.JsonFileIdmDocumentStore;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IdmUserAdminServletTest {

    @TempDir
    Path tempDir;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private StringWriter responseWriter;
    private IdmRealmService realmService;
    private IdmUserAdminServlet servlet;

    @BeforeEach
    void setUp() throws Exception {
        realmService = new IdmRealmService(new JsonFileIdmDocumentStore(tempDir));
        servlet = new IdmUserAdminServlet(realmService);
        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    @Test
    void getReturnsEmptyDocumentRealm() throws Exception {
        servlet.doGet(request, response);

        verify(response).setContentType("application/json");
        assertTrue(responseWriter.toString().contains("\"provider\":\"document\""));
        assertTrue(responseWriter.toString().contains("\"users\":[]"));
    }

    @Test
    void postCreatesUser() throws Exception {
        when(request.getParameter("version")).thenReturn("0");
        when(request.getParameter("loginName")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn("secret");
        when(request.getParameter("roles")).thenReturn("role1,role2");

        servlet.doPost(request, response);

        ArgumentCaptor<Integer> statusCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(response).setStatus(statusCaptor.capture());
        assertEquals(HttpServletResponse.SC_CREATED, statusCaptor.getValue());
        assertTrue(responseWriter.toString().contains("\"loginName\":\"alice\""));
    }

    @Test
    void postRejectsMissingCredentials() throws Exception {
        when(request.getParameter("loginName")).thenReturn("");
        when(request.getParameter("password")).thenReturn("secret");

        servlet.doPost(request, response);

        ArgumentCaptor<Integer> statusCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(response).setStatus(statusCaptor.capture());
        assertEquals(HttpServletResponse.SC_BAD_REQUEST, statusCaptor.getValue());
        assertTrue(responseWriter.toString().contains("loginName and password are required"));
    }

    @Test
    void putUpdatesUser() throws Exception {
        var created = realmService.createUserSnapshot(IdmDocumentStores.DEFAULT_DOCUMENT_ID, 0L, "alice", "secret",
                java.util.List.of("role1"));
        String userId = created.getUsers().get(0).getId();

        when(request.getParameter("version")).thenReturn(String.valueOf(created.getVersion()));
        when(request.getParameter("userId")).thenReturn(userId);
        when(request.getParameter("password")).thenReturn("new-secret");
        when(request.getParameter("roles")).thenReturn("role1,role2");
        when(request.getParameter("enabled")).thenReturn("false");

        servlet.doPut(request, response);

        assertTrue(responseWriter.toString().contains("\"enabled\":\"false\""));
        assertTrue(responseWriter.toString().contains("\"role1\""));
        assertTrue(responseWriter.toString().contains("\"role2\""));
    }

    @Test
    void deleteRemovesUser() throws Exception {
        var created = realmService.createUserSnapshot(IdmDocumentStores.DEFAULT_DOCUMENT_ID, 0L, "alice", "secret",
                java.util.List.of("role1"));
        String userId = created.getUsers().get(0).getId();

        when(request.getParameter("version")).thenReturn(String.valueOf(created.getVersion()));
        when(request.getParameter("userId")).thenReturn(userId);

        servlet.doDelete(request, response);

        assertTrue(responseWriter.toString().contains("\"users\":[]"));
    }

    @Test
    void postReturnsConflictWhenVersionStale() throws Exception {
        realmService.createUserSnapshot(IdmDocumentStores.DEFAULT_DOCUMENT_ID, 0L, "alice", "secret",
                java.util.List.of("role1"));

        when(request.getParameter("version")).thenReturn("0");
        when(request.getParameter("loginName")).thenReturn("bob");
        when(request.getParameter("password")).thenReturn("secret");
        when(request.getParameter("roles")).thenReturn("role1");

        servlet.doPost(request, response);

        ArgumentCaptor<Integer> statusCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(response).setStatus(statusCaptor.capture());
        assertEquals(HttpServletResponse.SC_CONFLICT, statusCaptor.getValue());
        assertTrue(responseWriter.toString().contains("\"actualVersion\":1"));
    }

    @Test
    void deleteRejectsMissingUserId() throws Exception {
        when(request.getParameter("version")).thenReturn("0");

        servlet.doDelete(request, response);

        ArgumentCaptor<Integer> statusCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(response).setStatus(statusCaptor.capture());
        assertEquals(HttpServletResponse.SC_BAD_REQUEST, statusCaptor.getValue());
    }
}
