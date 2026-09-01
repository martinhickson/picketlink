package org.picketlink.idm.rest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.RelationshipManager;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.model.basic.BasicModel;
import org.picketlink.idm.model.basic.Group;
import org.picketlink.idm.model.basic.User;

/**
 * SCIM 2.0 (RFC 7643/7644) identity service over a configured IDM {@link PartitionManager} —
 * the standardized REST API corporate applications already speak (Okta, Entra ID, HR sync,
 * provisioning tools). Upgrades the SCIM 1.1 endpoints in {@code modules/rest} to the current
 * spec as a plain servlet with no CDI dependency.
 *
 * <p>Resources (relative to the servlet mapping, typically {@code /scim/v2}):
 * {@code /ServiceProviderConfig}, {@code /Users}, {@code /Users/{id}}, {@code /Groups},
 * {@code /Groups/{id}}. Filtering supports the corporate-sync essentials
 * ({@code userName eq "x"}, {@code displayName eq "x"}); PATCH is advertised as unsupported
 * (use PUT). Passwords are set through the SCIM {@code passwords} attribute and verified via
 * IDM's credential pipeline. Point the OIDC {@code IdmSubjectAuthenticator} or a SAML login
 * at the same partition manager and SCIM-provisioned users authenticate immediately.
 *
 * <p>Every request must pass the configured {@link IdentityRestAccess} (init-param
 * {@code identityRestToken} for static-token mode; deny-all otherwise).
 */
public class ScimServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final String SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
    private static final String SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
    private static final String SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    private static final String SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
    private static final String SCHEMA_SPC = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

    public static final String INIT_PARAM_TOKEN = "identityRestToken";

    private transient PartitionManager partitionManager;
    private transient IdentityRestAccess access = IdentityRestAccess.DENY_ALL;

    public ScimServlet() {
    }

    public ScimServlet(PartitionManager partitionManager, IdentityRestAccess access) {
        this.partitionManager = partitionManager;
        this.access = access;
    }

    @Override
    public void init() {
        if (partitionManager == null) {
            Object configured = getServletContext().getAttribute(PartitionManager.class.getName());
            if (configured instanceof PartitionManager) {
                partitionManager = (PartitionManager) configured;
            }
        }
        String token = getInitParameter(INIT_PARAM_TOKEN);
        if (token != null && !token.isBlank()) {
            access = new IdentityRestAccess.StaticToken(token);
        }
        if (partitionManager == null) {
            throw new IllegalStateException("PartitionManager must be configured"
                    + " (servlet context attribute or constructor)");
        }
    }

    private IdentityManager idm() {
        return partitionManager.createIdentityManager();
    }

    private RelationshipManager rel() {
        return partitionManager.createRelationshipManager();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!authorized(request, response)) {
            return;
        }
        String[] path = path(request);
        String filter = request.getParameter("filter");
        if (is("ServiceProviderConfig", path)) {
            writeJson(response, 200, serviceProviderConfig());
        } else if (is("Users", path) && path.length == 1) {
            listUsers(response, filter);
        } else if (is("Users", path) && path.length == 2) {
            findUser(path[1], response);
        } else if (is("Groups", path) && path.length == 1) {
            listGroups(response, filter);
        } else if (is("Groups", path) && path.length == 2) {
            findGroup(path[1], response);
        } else {
            scimError(response, 404, "resource not found");
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!authorized(request, response)) {
            return;
        }
        String[] path = path(request);
        Json body = Json.parse(read(request));
        if (is("Users", path) && path.length == 1) {
            createUser(body, response);
        } else if (is("Groups", path) && path.length == 1) {
            createGroup(body, response);
        } else {
            scimError(response, 404, "resource not found");
        }
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!authorized(request, response)) {
            return;
        }
        String[] path = path(request);
        Json body = Json.parse(read(request));
        if (is("Users", path) && path.length == 2) {
            updateUser(path[1], body, response);
        } else if (is("Groups", path) && path.length == 2) {
            updateGroup(path[1], body, response);
        } else {
            scimError(response, 404, "resource not found");
        }
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!authorized(request, response)) {
            return;
        }
        String[] path = path(request);
        if (is("Users", path) && path.length == 2) {
            User user = userById(path[1]);
            if (user == null) {
                scimError(response, 404, "user not found");
                return;
            }
            idm().remove(user);
            writeStatus(response, 204);
        } else if (is("Groups", path) && path.length == 2) {
            Group group = groupById(path[1]);
            if (group == null) {
                scimError(response, 404, "group not found");
                return;
            }
            idm().remove(group);
            writeStatus(response, 204);
        } else {
            scimError(response, 404, "resource not found");
        }
    }

    // --- ServiceProviderConfig (RFC 7644 section 4)

    private static String serviceProviderConfig() {
        return "{\"schemas\":[\"" + SCHEMA_SPC + "\"],"
                + "\"patching\":{\"supported\":false},"
                + "\"filter\":{\"supported\":true,\"maxResults\":200},"
                + "\"changePassword\":{\"supported\":true},"
                + "\"sort\":{\"supported\":false},"
                + "\"authenticationSchemes\":[{\"name\":\"OAuth Bearer\",\"description\":\"Bearer token\"}]}";
    }

    // --- Users (RFC 7644 section 3.3)

    private void listUsers(HttpServletResponse response, String filter) throws IOException {
        List<User> users = idm().createIdentityQuery(User.class).getResultList();
        String userName = eqValue(filter, "userName");
        StringBuilder json = new StringBuilder("{\"schemas\":[\"" + SCHEMA_LIST + "\"],"
                + "\"totalResults\":0,\"startIndex\":1,\"itemsPerPage\":0,\"Resources\":[");
        int matches = 0;
        for (User user : users) {
            if (userName != null && !userName.equals(user.getLoginName())) {
                continue;
            }
            if (matches > 0) {
                json.append(',');
            }
            json.append(userJson(user));
            matches++;
        }
        json.append("]}");
        writeJson(response, 200, withCounts(json.toString(), matches));
    }

    private void findUser(String id, HttpServletResponse response) throws IOException {
        User user = userById(id);
        if (user == null) {
            scimError(response, 404, "user not found");
            return;
        }
        writeJson(response, 200, userJson(user));
    }

    private void createUser(Json body, HttpServletResponse response) throws IOException {
        String userName = body.string("userName");
        if (userName == null || userName.isBlank()) {
            scimError(response, 400, "userName is required");
            return;
        }
        if (BasicModel.getUser(idm(), userName) != null) {
            scimError(response, 409, "user already exists");
            return;
        }
        User user = new User(userName);
        applyUserAttributes(user, body);
        idm().add(user);
        String password = passwordOf(body);
        if (password != null) {
            idm().updateCredential(user, new Password(password));
        }
        writeJson(response, 201, userJson(BasicModel.getUser(idm(), userName)));
    }

    private void updateUser(String id, Json body, HttpServletResponse response) throws IOException {
        User user = userById(id);
        if (user == null) {
            scimError(response, 404, "user not found");
            return;
        }
        applyUserAttributes(user, body);
        idm().update(user);
        String password = passwordOf(body);
        if (password != null) {
            idm().updateCredential(user, new Password(password));
        }
        writeJson(response, 200, userJson(BasicModel.getUser(idm(), user.getLoginName())));
    }

    private static void applyUserAttributes(User user, Json body) {
        Json name = body.object("name");
        if (name != null) {
            user.setFirstName(name.string("givenName"));
            user.setLastName(name.string("familyName"));
        }
        List<Json> emails = body.array("emails");
        if (emails != null && !emails.isEmpty()) {
            user.setEmail(emails.get(0).string("value"));
        }
    }

    private static String passwordOf(Json body) {
        List<Json> passwords = body.array("passwords");
        if (passwords != null) {
            for (Json password : passwords) {
                if (Boolean.parseBoolean(String.valueOf(password.value("primary")))) {
                    return password.string("value");
                }
            }
        }
        return null;
    }

    private static String userJson(User user) {
        StringBuilder json = new StringBuilder("{\"schemas\":[\"" + SCHEMA_USER + "\"]");
        json.append(",\"id\":\"").append(Escape.json(user.getId())).append('"');
        json.append(",\"userName\":\"").append(Escape.json(user.getLoginName())).append('"');
        boolean hasName = user.getFirstName() != null || user.getLastName() != null;
        if (hasName) {
            json.append(",\"name\":{");
            boolean first = true;
            if (user.getFirstName() != null) {
                json.append("\"givenName\":\"").append(Escape.json(user.getFirstName())).append('"');
                first = false;
            }
            if (user.getLastName() != null) {
                if (!first) {
                    json.append(',');
                }
                json.append("\"familyName\":\"").append(Escape.json(user.getLastName())).append('"');
            }
            json.append('}');
        }
        if (user.getEmail() != null) {
            json.append(",\"emails\":[{\"value\":\"").append(Escape.json(user.getEmail()))
                    .append("\",\"primary\":true}]");
        }
        json.append(",\"active\":true}");
        return json.toString();
    }

    private User userById(String id) {
        for (User user : idm().createIdentityQuery(User.class).getResultList()) {
            if (user.getId() != null && user.getId().equals(id)) {
                return user;
            }
        }
        return null;
    }

    // --- Groups (RFC 7644 section 3.4)

    private void listGroups(HttpServletResponse response, String filter) throws IOException {
        List<Group> groups = idm().createIdentityQuery(Group.class).getResultList();
        String displayName = eqValue(filter, "displayName");
        StringBuilder json = new StringBuilder("{\"schemas\":[\"" + SCHEMA_LIST + "\"],"
                + "\"totalResults\":0,\"startIndex\":1,\"itemsPerPage\":0,\"Resources\":[");
        int matches = 0;
        for (Group group : groups) {
            if (displayName != null && !displayName.equals(group.getName())) {
                continue;
            }
            if (matches > 0) {
                json.append(',');
            }
            json.append(groupJson(group));
            matches++;
        }
        json.append("]}");
        writeJson(response, 200, withCounts(json.toString(), matches));
    }

    private void findGroup(String id, HttpServletResponse response) throws IOException {
        Group group = groupById(id);
        if (group == null) {
            scimError(response, 404, "group not found");
            return;
        }
        writeJson(response, 200, groupJson(group));
    }

    private void createGroup(Json body, HttpServletResponse response) throws IOException {
        String displayName = body.string("displayName");
        if (displayName == null || displayName.isBlank()) {
            scimError(response, 400, "displayName is required");
            return;
        }
        if (BasicModel.getGroup(idm(), displayName) != null) {
            scimError(response, 409, "group already exists");
            return;
        }
        idm().add(new Group(displayName));
        Group group = BasicModel.getGroup(idm(), displayName);
        applyMembers(group, body.array("members"));
        writeJson(response, 201, groupJson(group));
    }

    private void updateGroup(String id, Json body, HttpServletResponse response) throws IOException {
        Group group = groupById(id);
        if (group == null) {
            scimError(response, 404, "group not found");
            return;
        }
        applyMembers(group, body.array("members"));
        writeJson(response, 200, groupJson(group));
    }

    /** PUT semantics: the members array replaces the current membership. */
    private void applyMembers(Group group, List<Json> members) {
        for (User existing : idm().createIdentityQuery(User.class).getResultList()) {
            if (BasicModel.isMember(rel(), existing, group)) {
                BasicModel.removeFromGroup(rel(), existing, group);
            }
        }
        if (members == null) {
            return;
        }
        for (Json member : members) {
            User user = BasicModel.getUser(idm(), member.string("userName"));
            if (user == null) {
                user = userById(String.valueOf(member.value("value")));
            }
            if (user != null) {
                BasicModel.addToGroup(rel(), user, group);
            }
        }
    }

    private String groupJson(Group group) {
        StringBuilder json = new StringBuilder("{\"schemas\":[\"" + SCHEMA_GROUP + "\"]");
        json.append(",\"id\":\"").append(Escape.json(group.getId())).append('"');
        json.append(",\"displayName\":\"").append(Escape.json(group.getName())).append('"');
        json.append(",\"members\":[");
        int i = 0;
        for (User user : idm().createIdentityQuery(User.class).getResultList()) {
            if (!BasicModel.isMember(rel(), user, group)) {
                continue;
            }
            if (i > 0) {
                json.append(',');
            }
            json.append("{\"value\":\"").append(Escape.json(user.getId())).append('"')
                    .append(",\"userName\":\"").append(Escape.json(user.getLoginName()))
                    .append("\",\"display\":\"").append(Escape.json(user.getLoginName())).append("\"}");
            i++;
        }
        json.append("]}");
        return json.toString();
    }

    private Group groupById(String id) {
        for (Group group : idm().createIdentityQuery(Group.class).getResultList()) {
            if (group.getId() != null && group.getId().equals(id)) {
                return group;
            }
        }
        return null;
    }

    // --- helpers

    /** Extracts {@code attributeName eq "value"} from a SCIM filter (the sync essentials). */
    private static String eqValue(String filter, String attributeName) {
        if (filter == null) {
            return null;
        }
        String marker = attributeName + " eq \"";
        int start = filter.indexOf(marker);
        if (start < 0) {
            return null;
        }
        int valueStart = start + marker.length();
        int end = filter.indexOf('"', valueStart);
        return end < 0 ? null : filter.substring(valueStart, end);
    }

    private static String withCounts(String json, int count) {
        return json.replace("\"totalResults\":0", "\"totalResults\":" + count)
                .replace("\"itemsPerPage\":0", "\"itemsPerPage\":" + count);
    }

    private boolean authorized(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (access.isAuthorized(request.getHeader("Authorization"))) {
            return true;
        }
        scimError(response, 401, "valid bearer token required");
        return false;
    }

    private static String read(HttpServletRequest request) throws IOException {
        try (InputStream in = request.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String[] path(HttpServletRequest request) {
        String pathInfo = request.getPathInfo();
        if (pathInfo == null || pathInfo.isEmpty() || "/".equals(pathInfo)) {
            return new String[0];
        }
        return pathInfo.substring(1).split("/");
    }

    private static boolean is(String root, String[] path) {
        return path.length > 0 && root.equals(path[0]);
    }

    private static void writeStatus(HttpServletResponse response, int status) throws IOException {
        response.setStatus(status);
    }

    private static void writeJson(HttpServletResponse response, int status, String json) throws IOException {
        response.setStatus(status);
        response.setContentType("application/scim+json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(json);
    }

    private static void scimError(HttpServletResponse response, int status, String detail) throws IOException {
        writeJson(response, status, "{\"schemas\":[\"" + SCHEMA_ERROR + "\"],\"status\":\""
                + status + "\",\"detail\":\"" + Escape.json(detail) + "\"}");
    }

    // --- minimal JSON reader (flat fields, nested objects, arrays of objects)

    static final class Json {

        private final Map<String, Object> values = new LinkedHashMap<>();

        private Json(String json) {
            parseObject(trim(json), this);
        }

        static Json parse(String json) {
            return new Json(json == null ? "" : json);
        }

        String string(String name) {
            Object value = values.get(name);
            return value == null ? null : String.valueOf(value);
        }

        Object value(String name) {
            return values.get(name);
        }

        Json object(String name) {
            Object value = values.get(name);
            return value instanceof Json ? (Json) value : null;
        }

        List<Json> array(String name) {
            Object value = values.get(name);
            if (value instanceof List) {
                List<Json> result = new ArrayList<>();
                for (Object item : (List<?>) value) {
                    if (item instanceof Json) {
                        result.add((Json) item);
                    }
                }
                return result;
            }
            return null;
        }

        private static void parseObject(String json, Json target) {
            int index = 0;
            while (index < json.length()) {
                int nameStart = json.indexOf('"', index);
                if (nameStart < 0) {
                    break;
                }
                int nameEnd = json.indexOf('"', nameStart + 1);
                int colon = json.indexOf(':', nameEnd + 1);
                if (nameEnd < 0 || colon < 0) {
                    break;
                }
                String name = json.substring(nameStart + 1, nameEnd);
                index = skipWhitespace(json, colon + 1);
                if (index >= json.length()) {
                    break;
                }
                char c = json.charAt(index);
                if (c == '{') {
                    int end = matching(json, index, '{', '}');
                    Json child = new Json("");
                    parseObject(json.substring(index + 1, end), child);
                    target.values.put(name, child);
                    index = end + 1;
                } else if (c == '[') {
                    int end = matching(json, index, '[', ']');
                    target.values.put(name, parseArray(json.substring(index + 1, end)));
                    index = end + 1;
                } else if (c == '"') {
                    int end = json.indexOf('"', index + 1);
                    target.values.put(name, json.substring(index + 1, end));
                    index = end + 1;
                } else {
                    int end = index;
                    while (end < json.length() && ",}".indexOf(json.charAt(end)) < 0) {
                        end++;
                    }
                    String raw = json.substring(index, end).trim();
                    target.values.put(name, "true".equals(raw) ? Boolean.TRUE
                            : "false".equals(raw) ? Boolean.FALSE : raw);
                    index = end;
                }
            }
        }

        private static List<Object> parseArray(String json) {
            List<Object> items = new ArrayList<>();
            int index = 0;
            while (index < json.length()) {
                index = skipWhitespace(json, index);
                if (index >= json.length()) {
                    break;
                }
                if (json.charAt(index) == ',') {
                    index++;
                    continue;
                }
                if (json.charAt(index) == '{') {
                    int end = matching(json, index, '{', '}');
                    Json child = new Json("");
                    parseObject(json.substring(index + 1, end), child);
                    items.add(child);
                    index = end + 1;
                } else if (json.charAt(index) == '"') {
                    int end = json.indexOf('"', index + 1);
                    items.add(json.substring(index + 1, end));
                    index = end + 1;
                } else {
                    int end = index;
                    while (end < json.length() && ",]".indexOf(json.charAt(end)) < 0) {
                        end++;
                    }
                    items.add(json.substring(index, end).trim());
                    index = end;
                }
            }
            return items;
        }

        private static int matching(String value, int start, char open, char close) {
            int depth = 0;
            for (int index = start; index < value.length(); index++) {
                char ch = value.charAt(index);
                if (ch == open) {
                    depth++;
                } else if (ch == close) {
                    depth--;
                    if (depth == 0) {
                        return index;
                    }
                }
            }
            return value.length() - 1;
        }

        private static int skipWhitespace(String value, int index) {
            while (index < value.length() && Character.isWhitespace(value.charAt(index))) {
                index++;
            }
            return index;
        }

        private static String trim(String json) {
            int start = json.indexOf('{');
            int end = json.lastIndexOf('}');
            return start >= 0 && end > start ? json.substring(start + 1, end) : "";
        }
    }

    /** JSON string escaper. */
    static final class Escape {

        private Escape() {
        }

        static String json(String value) {
            if (value == null) {
                return "";
            }
            StringBuilder escaped = new StringBuilder(value.length());
            for (int i = 0; i < value.length(); i++) {
                char ch = value.charAt(i);
                if (ch == '"' || ch == '\\') {
                    escaped.append('\\').append(ch);
                } else if (ch == '\n') {
                    escaped.append("\\n");
                } else if (ch == '\r') {
                    escaped.append("\\r");
                } else if (ch == '\t') {
                    escaped.append("\\t");
                } else if (ch < 0x20) {
                    escaped.append(String.format("\\u%04x", (int) ch));
                } else {
                    escaped.append(ch);
                }
            }
            return escaped.toString();
        }
    }
}
