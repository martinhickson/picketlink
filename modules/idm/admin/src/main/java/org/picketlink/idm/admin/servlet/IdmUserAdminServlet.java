package org.picketlink.idm.admin.servlet;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.picketlink.idm.document.IdmDocumentStores;
import org.picketlink.idm.document.IdmRealmService;
import org.picketlink.idm.document.OptimisticLockException;
import org.picketlink.idm.realm.IdmRealmSnapshot;

public class IdmUserAdminServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient IdmRealmService realmService;

    @Override
    public void init() {
        if (realmService == null) {
            realmService = new IdmRealmService();
        }
    }

    public IdmUserAdminServlet() {
    }

    public IdmUserAdminServlet(IdmRealmService realmService) {
        this.realmService = realmService;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        String documentId = documentId(request);
        IdmRealmSnapshot snapshot = realmService.loadRealmSnapshot(documentId);
        response.getWriter().write(IdmUserAdminJsonWriter.writeRealm(snapshot));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        String documentId = documentId(request);
        long version = parseLong(request.getParameter("version"), 0L);
        String loginName = request.getParameter("loginName");
        String password = request.getParameter("password");
        List<String> roles = parseRoles(request.getParameter("roles"));
        if (loginName == null || loginName.isBlank() || password == null || password.isBlank()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmUserAdminJsonWriter.writeError("loginName and password are required"));
            return;
        }
        try {
            IdmRealmSnapshot updated = realmService.createUserSnapshot(
                    documentId, version, loginName.trim(), password, roles);
            response.setStatus(HttpServletResponse.SC_CREATED);
            response.getWriter().write(IdmUserAdminJsonWriter.writeRealm(updated));
        } catch (OptimisticLockException ex) {
            response.setStatus(HttpServletResponse.SC_CONFLICT);
            response.getWriter().write(IdmUserAdminJsonWriter.writeConflict(ex.getActualVersion()));
        } catch (IllegalArgumentException ex) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmUserAdminJsonWriter.writeError(ex.getMessage()));
        }
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        String documentId = documentId(request);
        long version = parseLong(request.getParameter("version"), -1L);
        String userId = request.getParameter("userId");
        if (userId == null || userId.isBlank() || version < 0L) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmUserAdminJsonWriter.writeError("userId and version are required"));
            return;
        }
        String password = request.getParameter("password");
        List<String> roles = request.getParameter("roles") != null ? parseRoles(request.getParameter("roles")) : null;
        Boolean enabled = request.getParameter("enabled") != null
                ? Boolean.valueOf(request.getParameter("enabled")) : null;
        try {
            IdmRealmSnapshot updated = realmService.updateUserSnapshot(
                    documentId, version, userId, password, roles, enabled);
            response.getWriter().write(IdmUserAdminJsonWriter.writeRealm(updated));
        } catch (OptimisticLockException ex) {
            response.setStatus(HttpServletResponse.SC_CONFLICT);
            response.getWriter().write(IdmUserAdminJsonWriter.writeConflict(ex.getActualVersion()));
        } catch (IllegalArgumentException ex) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmUserAdminJsonWriter.writeError(ex.getMessage()));
        }
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        String documentId = documentId(request);
        long version = parseLong(request.getParameter("version"), -1L);
        String userId = request.getParameter("userId");
        if (userId == null || userId.isBlank() || version < 0L) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmUserAdminJsonWriter.writeError("userId and version are required"));
            return;
        }
        try {
            IdmRealmSnapshot updated = realmService.deleteUserSnapshot(documentId, version, userId);
            response.getWriter().write(IdmUserAdminJsonWriter.writeRealm(updated));
        } catch (OptimisticLockException ex) {
            response.setStatus(HttpServletResponse.SC_CONFLICT);
            response.getWriter().write(IdmUserAdminJsonWriter.writeConflict(ex.getActualVersion()));
        } catch (IllegalArgumentException ex) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(IdmUserAdminJsonWriter.writeError(ex.getMessage()));
        }
    }

    private static String documentId(HttpServletRequest request) {
        String documentId = request.getParameter("documentId");
        if (documentId == null || documentId.isBlank()) {
            return IdmDocumentStores.DEFAULT_DOCUMENT_ID;
        }
        return documentId.trim();
    }

    private static long parseLong(String value, long defaultValue) {
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return Long.parseLong(value.trim());
    }

    private static List<String> parseRoles(String roles) {
        if (roles == null || roles.isBlank()) {
            return Arrays.asList("role1");
        }
        return Arrays.asList(roles.split("\\s*,\\s*"));
    }
}
