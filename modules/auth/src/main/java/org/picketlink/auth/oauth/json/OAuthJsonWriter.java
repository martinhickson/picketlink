package org.picketlink.auth.oauth.json;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.TokenResponse;

public final class OAuthJsonWriter {

    private OAuthJsonWriter() {
    }

    public static String writeTokenResponse(TokenResponse response) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendStringField(json, OAuthConstants.ACCESS_TOKEN, response.getAccessToken(), true);
        appendStringField(json, OAuthConstants.TOKEN_TYPE, response.getTokenType(), false);
        appendNumberField(json, OAuthConstants.EXPIRES_IN, response.getExpiresIn(), false);
        if (response.getScope() != null && !response.getScope().isBlank()) {
            appendStringField(json, OAuthConstants.SCOPE, response.getScope(), false);
        }
        json.append('}');
        return json.toString();
    }

    public static String writeErrorResponse(OAuthErrorResponse error) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendStringField(json, OAuthConstants.ERROR, error.getError(), true);
        if (error.getErrorDescription() != null && !error.getErrorDescription().isBlank()) {
            appendStringField(json, OAuthConstants.ERROR_DESCRIPTION, error.getErrorDescription(), false);
        }
        json.append('}');
        return json.toString();
    }

    private static void appendStringField(StringBuilder json, String name, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(escape(name)).append("\":\"").append(escape(value)).append('"');
    }

    private static void appendNumberField(StringBuilder json, String name, long value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(escape(name)).append("\":").append(value);
    }

    public static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) ch));
                    } else {
                        escaped.append(ch);
                    }
            }
        }
        return escaped.toString();
    }
}
