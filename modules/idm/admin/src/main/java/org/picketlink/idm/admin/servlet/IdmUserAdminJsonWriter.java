package org.picketlink.idm.admin.servlet;

import org.picketlink.idm.realm.IdmRealmSnapshot;

public final class IdmUserAdminJsonWriter {

    private IdmUserAdminJsonWriter() {
    }

    public static String writeRealm(IdmRealmSnapshot snapshot) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendField(json, "documentId", snapshot.getDocumentId(), true);
        appendField(json, "version", Long.toString(snapshot.getVersion()), false);
        appendField(json, "provider", snapshot.getProvider(), false);
        if (snapshot.getScimBaseUrl() != null && !snapshot.getScimBaseUrl().isBlank()) {
            appendField(json, "scimBaseUrl", snapshot.getScimBaseUrl(), false);
        }
        appendStringArray(json, "roles", snapshot.getRoles(), false);
        appendStringArray(json, "groups", snapshot.getGroups(), false);
        json.append(",\"users\":[");
        for (int i = 0; i < snapshot.getUsers().size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            appendUserObject(json, snapshot.getUsers().get(i));
        }
        json.append("]}");
        return json.toString();
    }

    public static String writeError(String message) {
        return "{\"error\":\"" + escape(message) + "\"}";
    }

    public static String writeConflict(long actualVersion) {
        return "{\"error\":\"Optimistic lock conflict\",\"actualVersion\":" + actualVersion + "}";
    }

    private static void appendUserObject(StringBuilder json, org.picketlink.idm.document.IdmUserRecord user) {
        json.append('{');
        appendField(json, "id", user.getId(), true);
        appendField(json, "loginName", user.getLoginName(), false);
        appendField(json, "enabled", Boolean.toString(user.isEnabled()), false);
        appendStringArray(json, "roles", user.getRoles(), false);
        json.append('}');
    }

    private static void appendStringArray(StringBuilder json, String key, java.util.List<String> values, boolean firstField) {
        if (!firstField) {
            json.append(',');
        }
        json.append('"').append(key).append("\":[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(escape(values.get(i))).append('"');
        }
        json.append(']');
    }

    private static void appendField(StringBuilder json, String key, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(key).append("\":\"").append(escape(value)).append('"');
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}
