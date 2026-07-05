package org.picketlink.idm.realm.config;

final class IdmRealmConfigJsonCodec {

    private IdmRealmConfigJsonCodec() {
    }

    static String write(IdmRealmConfigDocument document) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendString(json, "provider", document.getProvider(), true);
        appendString(json, "scimBaseUrl", document.getScimBaseUrl(), false);
        appendBoolean(json, "useDefaultBaseUrl", document.isUseDefaultBaseUrl(), false);
        appendString(json, "scimContextPath", document.getScimContextPath(), false);
        appendString(json, "bearerToken", document.getBearerToken(), false);
        appendBoolean(json, "syncToDocument", document.isSyncToDocument(), false);
        appendString(json, "usersPath", document.getUsersPath(), false);
        appendString(json, "groupsPath", document.getGroupsPath(), false);
        appendString(json, "rolesPath", document.getRolesPath(), false);
        json.append('}');
        return json.toString();
    }

    static IdmRealmConfigDocument read(String json) {
        if (json == null || json.isBlank()) {
            return IdmRealmConfigDocument.defaults();
        }
        return new IdmRealmConfigDocument(
                readString(json, "provider"),
                valueOrEmpty(readString(json, "scimBaseUrl")),
                readBoolean(json, "useDefaultBaseUrl", true),
                readString(json, "scimContextPath"),
                valueOrEmpty(readString(json, "bearerToken")),
                readBoolean(json, "syncToDocument", true),
                readString(json, "usersPath"),
                readString(json, "groupsPath"),
                readString(json, "rolesPath"));
    }

    private static String valueOrEmpty(String value) {
        return value == null ? "" : value;
    }

    private static void appendString(StringBuilder json, String key, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(key).append("\":\"").append(escape(value == null ? "" : value)).append('"');
    }

    private static void appendBoolean(StringBuilder json, String key, boolean value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(key).append("\":").append(value);
    }

    private static String readString(String json, String field) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return null;
        }
        int colon = json.indexOf(':', fieldIndex + marker.length());
        if (colon < 0) {
            return null;
        }
        int quoteStart = json.indexOf('"', colon + 1);
        if (quoteStart < 0) {
            return null;
        }
        int quoteEnd = json.indexOf('"', quoteStart + 1);
        if (quoteEnd < 0) {
            return null;
        }
        return unescape(json.substring(quoteStart + 1, quoteEnd));
    }

    private static boolean readBoolean(String json, String field, boolean defaultValue) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return defaultValue;
        }
        int colon = json.indexOf(':', fieldIndex + marker.length());
        if (colon < 0) {
            return defaultValue;
        }
        int trueIndex = json.indexOf("true", colon + 1);
        int falseIndex = json.indexOf("false", colon + 1);
        if (trueIndex >= 0 && (falseIndex < 0 || trueIndex < falseIndex)) {
            return true;
        }
        if (falseIndex >= 0) {
            return false;
        }
        return defaultValue;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    private static String unescape(String value) {
        return value.replace("\\n", "\n").replace("\\r", "\r").replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
