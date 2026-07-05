package org.picketlink.idm.document;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class IdmDocumentJsonCodec {

    private IdmDocumentJsonCodec() {
    }

    static String write(IdmRealmDocument document) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendString(json, "documentId", document.getDocumentId(), true);
        appendLong(json, "version", document.getVersion(), false);
        json.append("\"users\":[");
        List<IdmUserRecord> users = document.getUsers();
        for (int i = 0; i < users.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            appendUser(json, users.get(i));
        }
        json.append("]}");
        return json.toString();
    }

    static IdmRealmDocument read(String documentId, String json) {
        if (json == null || json.trim().isEmpty()) {
            return IdmRealmDocument.empty(documentId);
        }
        String resolvedDocumentId = readString(json, "documentId");
        if (resolvedDocumentId == null || resolvedDocumentId.isBlank()) {
            resolvedDocumentId = documentId;
        }
        long version = readLong(json, "version", 0L);
        List<IdmUserRecord> users = readUsers(json);
        return new IdmRealmDocument(resolvedDocumentId, version, users);
    }

    private static List<IdmUserRecord> readUsers(String json) {
        List<IdmUserRecord> users = new ArrayList<IdmUserRecord>();
        int usersIndex = json.indexOf("\"users\"");
        if (usersIndex < 0) {
            return users;
        }
        int arrayStart = json.indexOf('[', usersIndex);
        if (arrayStart < 0) {
            return users;
        }
        int index = arrayStart + 1;
        while (index < json.length()) {
            index = skipWhitespace(json, index);
            if (index >= json.length() || json.charAt(index) == ']') {
                break;
            }
            if (json.charAt(index) == ',') {
                index++;
                continue;
            }
            if (json.charAt(index) != '{') {
                break;
            }
            int objectEnd = findMatching(json, index, '{', '}');
            users.add(parseUser(json.substring(index, objectEnd + 1)));
            index = objectEnd + 1;
        }
        return users;
    }

    private static IdmUserRecord parseUser(String objectJson) {
        String id = readString(objectJson, "id");
        String loginName = readString(objectJson, "loginName");
        String passwordHash = readString(objectJson, "passwordHash");
        List<String> roles = readStringArray(objectJson, "roles");
        boolean enabled = readBoolean(objectJson, "enabled", true);
        return new IdmUserRecord(id, loginName, passwordHash, roles, enabled);
    }

    private static void appendUser(StringBuilder json, IdmUserRecord user) {
        json.append('{');
        appendString(json, "id", user.getId(), true);
        appendString(json, "loginName", user.getLoginName(), false);
        appendString(json, "passwordHash", user.getPasswordHash(), false);
        appendStringArray(json, "roles", user.getRoles(), false);
        appendBoolean(json, "enabled", user.isEnabled(), false);
        json.append('}');
    }

    private static void appendString(StringBuilder json, String key, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(escape(key)).append("\":\"").append(escape(value)).append('"');
    }

    private static void appendLong(StringBuilder json, String key, long value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(escape(key)).append("\":").append(value);
    }

    private static void appendBoolean(StringBuilder json, String key, boolean value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(escape(key)).append("\":").append(value);
    }

    private static void appendStringArray(StringBuilder json, String key, List<String> values, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(escape(key)).append("\":[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(escape(values.get(i))).append('"');
        }
        json.append(']');
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

    private static long readLong(String json, String field, long defaultValue) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return defaultValue;
        }
        int colon = json.indexOf(':', fieldIndex + marker.length());
        if (colon < 0) {
            return defaultValue;
        }
        int end = colon + 1;
        while (end < json.length() && Character.isWhitespace(json.charAt(end))) {
            end++;
        }
        int valueEnd = end;
        while (valueEnd < json.length() && (Character.isDigit(json.charAt(valueEnd)) || json.charAt(valueEnd) == '-')) {
            valueEnd++;
        }
        if (valueEnd == end) {
            return defaultValue;
        }
        return Long.parseLong(json.substring(end, valueEnd));
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

    private static List<String> readStringArray(String json, String field) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return Collections.emptyList();
        }
        int arrayStart = json.indexOf('[', fieldIndex);
        if (arrayStart < 0) {
            return Collections.emptyList();
        }
        Set<String> values = new LinkedHashSet<String>();
        int index = arrayStart + 1;
        while (index < json.length()) {
            index = skipWhitespace(json, index);
            if (index >= json.length() || json.charAt(index) == ']') {
                break;
            }
            if (json.charAt(index) == ',') {
                index++;
                continue;
            }
            if (json.charAt(index) != '"') {
                break;
            }
            int quoteEnd = json.indexOf('"', index + 1);
            if (quoteEnd < 0) {
                break;
            }
            values.add(unescape(json.substring(index + 1, quoteEnd)));
            index = quoteEnd + 1;
        }
        return new ArrayList<String>(values);
    }

    private static int skipWhitespace(String json, int index) {
        while (index < json.length() && Character.isWhitespace(json.charAt(index))) {
            index++;
        }
        return index;
    }

    private static int findMatching(String json, int start, char open, char close) {
        int depth = 0;
        for (int i = start; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (ch == open) {
                depth++;
            } else if (ch == close) {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return json.length() - 1;
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    private static String unescape(String value) {
        return value.replace("\\n", "\n").replace("\\r", "\r").replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
