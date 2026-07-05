package org.picketlink.auth.oauth.client.store;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;

public final class ClientRegistrationJsonCodec {

    private static final int VERSION = 1;

    private ClientRegistrationJsonCodec() {
    }

    public static String write(List<RegisteredClient> clients) {
        StringBuilder json = new StringBuilder();
        json.append("{\"version\":").append(VERSION).append(",\"clients\":[");
        for (int i = 0; i < clients.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            appendClient(json, clients.get(i));
        }
        json.append("]}");
        return json.toString();
    }

    public static List<RegisteredClient> read(String json) {
        if (json == null || json.trim().isEmpty()) {
            return new ArrayList<RegisteredClient>();
        }
        List<RegisteredClient> clients = new ArrayList<RegisteredClient>();
        int clientsIndex = json.indexOf("\"clients\"");
        if (clientsIndex < 0) {
            return clients;
        }
        int arrayStart = json.indexOf('[', clientsIndex);
        if (arrayStart < 0) {
            return clients;
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
            clients.add(parseClient(json.substring(index, objectEnd + 1)));
            index = objectEnd + 1;
        }
        return clients;
    }

    private static void appendClient(StringBuilder json, RegisteredClient client) {
        json.append('{');
        appendString(json, "clientId", client.getClientId(), true);
        appendString(json, "clientSecret", client.getClientSecret(), false);
        appendStringArray(json, "scopes", client.getScopes(), false);
        appendString(json, "tokenEndpointAuthMethod",
                client.getTokenEndpointAuthMethod().getValue(), false);
        json.append('}');
    }

    private static RegisteredClient parseClient(String objectJson) {
        String clientId = readString(objectJson, "clientId");
        String clientSecret = readString(objectJson, "clientSecret");
        Set<String> scopes = readStringArray(objectJson, "scopes");
        String authMethod = readString(objectJson, "tokenEndpointAuthMethod");
        RegisteredClient.Builder builder = RegisteredClient.builder(clientId, clientSecret);
        builder.scopes(scopes);
        if (OAuthConstants.TOKEN_ENDPOINT_AUTH_POST.equals(authMethod)) {
            builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST);
        } else {
            builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
        }
        return builder.build();
    }

    private static void appendString(StringBuilder json, String name, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":\"")
                .append(OAuthJsonWriter.escape(value)).append('"');
    }

    private static void appendStringArray(StringBuilder json, String name, Set<String> values, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":[");
        int i = 0;
        for (String value : values) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(OAuthJsonWriter.escape(value)).append('"');
            i++;
        }
        json.append(']');
    }

    private static String readString(String json, String fieldName) {
        String marker = "\"" + fieldName + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return "";
        }
        int colon = json.indexOf(':', fieldIndex + marker.length());
        if (colon < 0) {
            return "";
        }
        int quoteStart = json.indexOf('"', colon + 1);
        if (quoteStart < 0) {
            return "";
        }
        StringBuilder value = new StringBuilder();
        int index = quoteStart + 1;
        while (index < json.length()) {
            char ch = json.charAt(index);
            if (ch == '"') {
                break;
            }
            if (ch == '\\' && index + 1 < json.length()) {
                char next = json.charAt(index + 1);
                if (next == 'n') {
                    value.append('\n');
                } else if (next == 'r') {
                    value.append('\r');
                } else if (next == 't') {
                    value.append('\t');
                } else if (next == '"') {
                    value.append('"');
                } else if (next == '\\') {
                    value.append('\\');
                } else {
                    value.append(next);
                }
                index += 2;
                continue;
            }
            value.append(ch);
            index++;
        }
        return value.toString();
    }

    private static Set<String> readStringArray(String json, String fieldName) {
        Set<String> values = new LinkedHashSet<String>();
        String marker = "\"" + fieldName + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return values;
        }
        int arrayStart = json.indexOf('[', fieldIndex);
        if (arrayStart < 0) {
            return values;
        }
        int arrayEnd = findMatching(json, arrayStart, '[', ']');
        String arrayJson = json.substring(arrayStart + 1, arrayEnd);
        int index = 0;
        while (index < arrayJson.length()) {
            index = skipWhitespace(arrayJson, index);
            if (index >= arrayJson.length()) {
                break;
            }
            if (arrayJson.charAt(index) == ',') {
                index++;
                continue;
            }
            if (arrayJson.charAt(index) != '"') {
                break;
            }
            int quoteEnd = arrayJson.indexOf('"', index + 1);
            while (quoteEnd > 0 && arrayJson.charAt(quoteEnd - 1) == '\\') {
                quoteEnd = arrayJson.indexOf('"', quoteEnd + 1);
            }
            if (quoteEnd < 0) {
                break;
            }
            values.add(arrayJson.substring(index + 1, quoteEnd));
            index = quoteEnd + 1;
        }
        return values;
    }

    private static int skipWhitespace(String value, int index) {
        while (index < value.length()) {
            char ch = value.charAt(index);
            if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
                break;
            }
            index++;
        }
        return index;
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
