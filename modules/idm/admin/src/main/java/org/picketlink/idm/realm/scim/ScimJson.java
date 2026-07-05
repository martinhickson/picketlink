package org.picketlink.idm.realm.scim;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class ScimJson {

    private ScimJson() {
    }

    static List<ScimRealmClient.ScimResource> parseListResponse(String json) {
        if (json == null || json.isBlank()) {
            return Collections.emptyList();
        }
        int resourcesIndex = json.indexOf("\"Resources\"");
        if (resourcesIndex < 0) {
            resourcesIndex = json.indexOf("\"resources\"");
        }
        if (resourcesIndex < 0) {
            if (json.trim().startsWith("{")) {
                return Collections.singletonList(parseResource(json));
            }
            return Collections.emptyList();
        }
        int arrayStart = json.indexOf('[', resourcesIndex);
        if (arrayStart < 0) {
            return Collections.emptyList();
        }
        List<ScimRealmClient.ScimResource> resources = new ArrayList<ScimRealmClient.ScimResource>();
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
            int end = findMatching(json, index, '{', '}');
            resources.add(parseResource(json.substring(index, end + 1)));
            index = end + 1;
        }
        return resources;
    }

    static ScimRealmClient.ScimResource parseResource(String json) {
        String id = readString(json, "id");
        String userName = firstNonBlank(readString(json, "userName"), readString(json, "displayName"));
        String displayName = firstNonBlank(readString(json, "displayName"), userName);
        boolean active = readBoolean(json, "active", true);
        List<String> groups = readGroupValues(json);
        return new ScimRealmClient.ScimResource(id, displayName, userName, active, groups);
    }

    private static List<String> readGroupValues(String json) {
        List<String> groups = new ArrayList<String>();
        int groupsIndex = json.indexOf("\"groups\"");
        if (groupsIndex < 0) {
            return groups;
        }
        int arrayStart = json.indexOf('[', groupsIndex);
        if (arrayStart < 0) {
            return groups;
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
            int end = findMatching(json, index, '{', '}');
            String groupObject = json.substring(index, end + 1);
            String value = firstNonBlank(readString(groupObject, "display"), readString(groupObject, "value"));
            if (value != null && !value.isBlank()) {
                groups.add(value.trim());
            }
            index = end + 1;
        }
        return groups;
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
        return json.indexOf("true", colon + 1) >= 0
                && (json.indexOf("false", colon + 1) < 0 || json.indexOf("true", colon + 1) < json.indexOf("false", colon + 1));
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
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

    static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    private static String unescape(String value) {
        return value.replace("\\n", "\n").replace("\\r", "\r").replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
