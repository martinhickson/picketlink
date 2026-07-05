package org.picketlink.idm.realm.scim;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Minimal SCIM 1.1 REST client for Users, Groups, and the PicketLink /Roles extension.
 */
public final class ScimRealmClient {

    private final String baseUrl;
    private final String bearerToken;
    private final String usersPath;
    private final String groupsPath;
    private final String rolesPath;

    public ScimRealmClient(String baseUrl, String bearerToken, String usersPath, String groupsPath, String rolesPath) {
        this.baseUrl = trimTrailingSlash(baseUrl);
        this.bearerToken = bearerToken == null ? "" : bearerToken;
        this.usersPath = usersPath;
        this.groupsPath = groupsPath;
        this.rolesPath = rolesPath;
    }

    public List<ScimResource> listUsers() throws IOException {
        return listResources(usersPath);
    }

    public List<ScimResource> listGroups() throws IOException {
        return listResources(groupsPath);
    }

    public List<ScimResource> listRoles() throws IOException {
        return listResources(rolesPath);
    }

    public ScimResource createUser(String userName, String password, boolean active, List<String> roleNames)
            throws IOException {
        StringBuilder json = new StringBuilder();
        json.append('{');
        json.append("\"userName\":\"").append(ScimJson.escape(userName)).append('"');
        json.append(",\"displayName\":\"").append(ScimJson.escape(userName)).append('"');
        json.append(",\"active\":").append(active);
        json.append(",\"password\":\"").append(ScimJson.escape(password)).append('"');
        appendGroupsArray(json, roleNames);
        json.append('}');
        String response = execute("POST", usersPath, json.toString());
        return ScimJson.parseResource(response);
    }

    public void deleteUser(String userId) throws IOException {
        execute("DELETE", usersPath + "/" + userId, null);
    }

    public ScimResource updateUser(String userId, String password, Boolean active, List<String> roleNames)
            throws IOException {
        StringBuilder json = new StringBuilder();
        json.append('{');
        boolean first = true;
        if (active != null) {
            json.append("\"active\":").append(active.booleanValue());
            first = false;
        }
        if (password != null && !password.isBlank()) {
            if (!first) {
                json.append(',');
            }
            json.append("\"password\":\"").append(ScimJson.escape(password)).append('"');
            first = false;
        }
        if (roleNames != null) {
            if (!first) {
                json.append(',');
            }
            appendGroupsArray(json, roleNames);
        }
        json.append('}');
        String response = execute("PUT", usersPath + "/" + userId, json.toString());
        return ScimJson.parseResource(response);
    }

    private List<ScimResource> listResources(String path) throws IOException {
        String response = execute("GET", path, null);
        return ScimJson.parseListResponse(response);
    }

    private String execute(String method, String path, String body) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        connection.setRequestMethod(method);
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("Content-Type", "application/json");
        if (!bearerToken.isBlank()) {
            connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
        }
        if (body != null) {
            connection.setDoOutput(true);
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            connection.setRequestProperty("Content-Length", Integer.toString(bytes.length));
            try (OutputStream output = connection.getOutputStream()) {
                output.write(bytes);
            }
        }
        int status = connection.getResponseCode();
        if (status >= 400) {
            String response = readStream(connection.getErrorStream());
            throw new IOException("SCIM " + method + " " + path + " failed with HTTP " + status + ": " + response);
        }
        if (status == HttpURLConnection.HTTP_NO_CONTENT) {
            return "";
        }
        return readStream(connection.getInputStream());
    }

    private static void appendGroupsArray(StringBuilder json, List<String> roleNames) {
        json.append(",\"groups\":[");
        for (int i = 0; i < roleNames.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append("{\"value\":\"").append(ScimJson.escape(roleNames.get(i))).append("\"}");
        }
        json.append(']');
    }

    private static String readStream(InputStream stream) throws IOException {
        if (stream == null) {
            return "";
        }
        try (InputStream input = stream; ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            input.transferTo(buffer);
            return buffer.toString(StandardCharsets.UTF_8);
        }
    }

    private static String trimTrailingSlash(String url) {
        if (url.endsWith("/") && url.length() > 1) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }

    public static final class ScimResource {
        private final String id;
        private final String displayName;
        private final String userName;
        private final boolean active;
        private final List<String> groups;

        public ScimResource(String id, String displayName, String userName, boolean active, List<String> groups) {
            this.id = id;
            this.displayName = displayName;
            this.userName = userName;
            this.active = active;
            this.groups = groups;
        }

        public String getId() {
            return id;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getUserName() {
            return userName;
        }

        public boolean isActive() {
            return active;
        }

        public List<String> getGroups() {
            return groups;
        }

        public String loginName() {
            if (userName != null && !userName.isBlank()) {
                return userName;
            }
            return displayName;
        }
    }

    public static List<String> distinctRoleNames(List<ScimResource> users, List<ScimResource> groups,
            List<ScimResource> roles) {
        Set<String> names = new LinkedHashSet<String>();
        for (ScimResource role : roles) {
            addName(names, role.getDisplayName());
            addName(names, role.getUserName());
        }
        for (ScimResource group : groups) {
            addName(names, group.getDisplayName());
            addName(names, group.getUserName());
        }
        for (ScimResource user : users) {
            names.addAll(user.getGroups());
        }
        names.remove("");
        return new ArrayList<String>(names);
    }

    public static List<String> groupNames(List<ScimResource> groups) {
        List<String> names = new ArrayList<String>();
        for (ScimResource group : groups) {
            addName(names, group.getDisplayName());
            if (group.getUserName() != null && !group.getUserName().isBlank()
                    && !names.contains(group.getUserName())) {
                names.add(group.getUserName());
            }
        }
        return names;
    }

    public static List<String> roleNames(List<ScimResource> roles) {
        List<String> names = new ArrayList<String>();
        for (ScimResource role : roles) {
            addName(names, role.getDisplayName());
            if (role.getUserName() != null && !role.getUserName().isBlank() && !names.contains(role.getUserName())) {
                names.add(role.getUserName());
            }
        }
        return names;
    }

    private static void addName(Set<String> names, String value) {
        if (value != null && !value.isBlank()) {
            names.add(value.trim());
        }
    }

    private static void addName(List<String> names, String value) {
        if (value != null && !value.isBlank() && !names.contains(value.trim())) {
            names.add(value.trim());
        }
    }
}
