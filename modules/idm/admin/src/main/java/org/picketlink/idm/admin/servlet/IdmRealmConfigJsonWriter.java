package org.picketlink.idm.admin.servlet;

import org.picketlink.idm.realm.config.IdmRealmConfigSnapshot;

public final class IdmRealmConfigJsonWriter {

    private IdmRealmConfigJsonWriter() {
    }

    public static String writeSnapshot(IdmRealmConfigSnapshot snapshot) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendField(json, "configFile", snapshot.getConfigFile(), true);
        appendField(json, "provider", snapshot.getDocument().getProvider(), false);
        appendField(json, "scimBaseUrl", snapshot.getDocument().getScimBaseUrl(), false);
        appendField(json, "useDefaultBaseUrl", Boolean.toString(snapshot.getDocument().isUseDefaultBaseUrl()), false);
        appendField(json, "defaultScimBaseUrl", snapshot.getDefaultScimBaseUrl(), false);
        appendField(json, "effectiveScimBaseUrl", snapshot.getEffectiveScimBaseUrl(), false);
        appendField(json, "scimContextPath", snapshot.getDocument().getScimContextPath(), false);
        appendField(json, "bearerToken", snapshot.getDocument().getBearerToken(), false);
        appendField(json, "syncToDocument", Boolean.toString(snapshot.getDocument().isSyncToDocument()), false);
        appendField(json, "usersPath", snapshot.getDocument().getUsersPath(), false);
        appendField(json, "groupsPath", snapshot.getDocument().getGroupsPath(), false);
        appendField(json, "rolesPath", snapshot.getDocument().getRolesPath(), false);
        json.append('}');
        return json.toString();
    }

    public static String writeError(String message) {
        return "{\"error\":\"" + escape(message) + "\"}";
    }

    private static void appendField(StringBuilder json, String key, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(key).append("\":\"").append(escape(value == null ? "" : value)).append('"');
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}
