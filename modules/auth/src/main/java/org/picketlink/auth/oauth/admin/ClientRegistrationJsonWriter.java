package org.picketlink.auth.oauth.admin;

import java.util.List;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;

public final class ClientRegistrationJsonWriter {

    private ClientRegistrationJsonWriter() {
    }

    public static String writeViews(List<ClientRegistrationView> views) {
        StringBuilder json = new StringBuilder();
        json.append('[');
        for (int i = 0; i < views.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            appendView(json, views.get(i));
        }
        json.append(']');
        return json.toString();
    }

    public static String writeView(ClientRegistrationView view) {
        StringBuilder json = new StringBuilder();
        appendView(json, view);
        return json.toString();
    }

    public static ClientRegistrationRequest readRequest(String json) {
        ClientRegistrationRequest request = new ClientRegistrationRequest();
        request.setClientId(readString(json, "clientId"));
        request.setClientSecret(readString(json, "clientSecret"));
        request.setTokenEndpointAuthMethod(readString(json, "tokenEndpointAuthMethod"));
        request.setScopes(readStringList(json, "scopes"));
        return request;
    }

    private static void appendView(StringBuilder json, ClientRegistrationView view) {
        json.append('{');
        appendString(json, "clientId", view.getClientId(), true);
        appendString(json, "clientSecret", view.getClientSecret(), false);
        appendStringArray(json, "scopes", view.getScopes(), false);
        appendString(json, "tokenEndpointAuthMethod", view.getTokenEndpointAuthMethod(), false);
        json.append('}');
    }

    private static void appendString(StringBuilder json, String name, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":\"")
                .append(OAuthJsonWriter.escape(value == null ? "" : value)).append('"');
    }

    private static void appendStringArray(StringBuilder json, String name, List<String> values, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":[");
        if (values != null) {
            for (int i = 0; i < values.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                json.append('"').append(OAuthJsonWriter.escape(values.get(i))).append('"');
            }
        }
        json.append(']');
    }

    private static String readString(String json, String fieldName) {
        String marker = "\"" + fieldName + "\"";
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
        return json.substring(quoteStart + 1, quoteEnd);
    }

    private static List<String> readStringList(String json, String fieldName) {
        List<String> values = new java.util.ArrayList<String>();
        String marker = "\"" + fieldName + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return values;
        }
        int arrayStart = json.indexOf('[', fieldIndex);
        if (arrayStart < 0) {
            return values;
        }
        int arrayEnd = json.indexOf(']', arrayStart);
        if (arrayEnd < 0) {
            return values;
        }
        String arrayJson = json.substring(arrayStart + 1, arrayEnd);
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
            values.add(arrayJson.substring(quoteStart + 1, quoteEnd));
            index = quoteEnd + 1;
        }
        return values;
    }
}
