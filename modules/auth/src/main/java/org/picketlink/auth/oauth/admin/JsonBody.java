package org.picketlink.auth.oauth.admin;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Minimal flat-JSON reader for admin request bodies: string fields, string arrays and numeric
 * fields at the top level of a JSON object. Matches the hand-rolled parser style of this module.
 */
public final class JsonBody {

    private final Map<String, String> values = new LinkedHashMap<>();
    private final Map<String, Set<String>> arrays = new LinkedHashMap<>();

    private JsonBody(String json) {
        if (json == null) {
            return;
        }
        int index = 0;
        while (index < json.length()) {
            int nameStart = json.indexOf('"', index);
            if (nameStart < 0) {
                break;
            }
            int nameEnd = json.indexOf('"', nameStart + 1);
            if (nameEnd < 0) {
                break;
            }
            String name = json.substring(nameStart + 1, nameEnd);
            int colon = json.indexOf(':', nameEnd + 1);
            if (colon < 0) {
                break;
            }
            int valueStart = colon + 1;
            while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
                valueStart++;
            }
            if (valueStart >= json.length()) {
                break;
            }
            if (json.charAt(valueStart) == '[') {
                int arrayEnd = findMatching(json, valueStart, '[', ']');
                arrays.put(name, parseArray(json.substring(valueStart + 1, arrayEnd)));
                index = arrayEnd + 1;
            } else {
                int valueEnd = valueStart;
                while (valueEnd < json.length() && ",}".indexOf(json.charAt(valueEnd)) < 0) {
                    valueEnd++;
                }
                values.put(name, unquote(json.substring(valueStart, valueEnd).trim()));
                index = valueEnd;
            }
        }
    }

    public static JsonBody parse(String json) {
        return new JsonBody(json);
    }

    public String string(String name) {
        String value = values.get(name);
        return value == null || value.isEmpty() ? null : value;
    }

    public long number(String name, long fallback) {
        String value = values.get(name);
        if (value == null) {
            return fallback;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }

    boolean has(String name) {
        return values.containsKey(name) || arrays.containsKey(name);
    }

    public Set<String> array(String name) {
        Set<String> value = arrays.get(name);
        return value == null ? new LinkedHashSet<>() : value;
    }

    private static Set<String> parseArray(String arrayJson) {
        Set<String> valuesInArray = new LinkedHashSet<>();
        int index = 0;
        while (index < arrayJson.length()) {
            int quoteStart = arrayJson.indexOf('"', index);
            if (quoteStart < 0) {
                break;
            }
            int quoteEnd = arrayJson.indexOf('"', quoteStart + 1);
            if (quoteEnd < 0) {
                break;
            }
            valuesInArray.add(arrayJson.substring(quoteStart + 1, quoteEnd));
            index = quoteEnd + 1;
        }
        return valuesInArray;
    }

    private static String unquote(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1)
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\")
                    .replace("\\n", "\n");
        }
        return value;
    }

    private static int findMatching(String value, int start, char open, char close) {
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
}
