package org.picketlink.auth.oauth.store;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.picketlink.auth.oauth.json.OAuthJsonWriter;

/**
 * Persisted signing-key document: which keystore holds the private material, which key is
 * active, and the metadata of every key (including rotated ones kept in the overlap window).
 */
public final class SigningKeyDocument {

    private String keystorePath;
    private String activeKid;
    private final List<SigningKeyRecord> keys = new ArrayList<>();

    public String getKeystorePath() {
        return keystorePath;
    }

    public void setKeystorePath(String keystorePath) {
        this.keystorePath = keystorePath;
    }

    public String getActiveKid() {
        return activeKid;
    }

    public void setActiveKid(String activeKid) {
        this.activeKid = activeKid;
    }

    public List<SigningKeyRecord> getKeys() {
        return keys;
    }

    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append('{');
        json.append("\"keystorePath\":\"").append(OAuthJsonWriter.escape(keystorePath == null ? "" : keystorePath))
                .append('"');
        json.append(",\"activeKid\":\"").append(OAuthJsonWriter.escape(activeKid == null ? "" : activeKid))
                .append('"');
        json.append(",\"keys\":[");
        for (int i = 0; i < keys.size(); i++) {
            SigningKeyRecord key = keys.get(i);
            if (i > 0) {
                json.append(',');
            }
            json.append('{');
            json.append("\"keyId\":\"").append(OAuthJsonWriter.escape(key.getKeyId())).append('"');
            json.append(",\"algorithm\":\"").append(OAuthJsonWriter.escape(key.getAlgorithm())).append('"');
            json.append(",\"keystoreAlias\":\"").append(OAuthJsonWriter.escape(key.getKeystoreAlias()))
                    .append('"');
            json.append(",\"active\":").append(key.isActive());
            json.append(",\"createdAt\":").append(key.getCreatedAtEpochSeconds());
            json.append('}');
        }
        json.append("]}");
        return json.toString();
    }

    public static SigningKeyDocument fromJson(String json) {
        SigningKeyDocument document = new SigningKeyDocument();
        if (json == null || json.isBlank()) {
            return document;
        }
        document.setKeystorePath(readString(json, "keystorePath"));
        document.setActiveKid(readString(json, "activeKid"));
        int keysIndex = json.indexOf("\"keys\"");
        int arrayStart = json.indexOf('[', keysIndex >= 0 ? keysIndex : 0);
        if (keysIndex < 0 || arrayStart < 0) {
            return document;
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
            int objectEnd = findMatching(json, index);
            String objectJson = json.substring(index, objectEnd + 1);
            document.getKeys().add(new SigningKeyRecord(
                    readString(objectJson, "keyId"),
                    readString(objectJson, "algorithm"),
                    readString(objectJson, "keystoreAlias"),
                    readBoolean(objectJson, "active"),
                    readLong(objectJson, "createdAt", Instant.now().getEpochSecond())));
            index = objectEnd + 1;
        }
        return document;
    }

    private static String readString(String json, String field) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return "";
        }
        int quoteStart = json.indexOf('"', fieldIndex + marker.length());
        int quoteEnd = quoteStart >= 0 ? json.indexOf('"', quoteStart + 1) : -1;
        if (quoteStart < 0 || quoteEnd < 0) {
            return "";
        }
        return json.substring(quoteStart + 1, quoteEnd);
    }

    private static boolean readBoolean(String json, String field) {
        return "true".equals(readRaw(json, field, "false"));
    }

    private static long readLong(String json, String field, long fallback) {
        String raw = readRaw(json, field, null);
        if (raw == null) {
            return fallback;
        }
        return Long.parseLong(raw.trim());
    }

    private static String readRaw(String json, String field, String fallback) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return fallback;
        }
        int colon = json.indexOf(':', fieldIndex + marker.length());
        if (colon < 0) {
            return fallback;
        }
        int end = colon + 1;
        while (end < json.length() && ",}".indexOf(json.charAt(end)) < 0) {
            end++;
        }
        return json.substring(colon + 1, end);
    }

    private static int skipWhitespace(String value, int index) {
        while (index < value.length() && Character.isWhitespace(value.charAt(index))) {
            index++;
        }
        return index;
    }

    private static int findMatching(String value, int start) {
        int depth = 0;
        for (int index = start; index < value.length(); index++) {
            char ch = value.charAt(index);
            if (ch == '{') {
                depth++;
            } else if (ch == '}') {
                depth--;
                if (depth == 0) {
                    return index;
                }
            }
        }
        return value.length() - 1;
    }
}
