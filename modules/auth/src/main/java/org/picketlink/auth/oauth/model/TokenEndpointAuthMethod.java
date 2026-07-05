package org.picketlink.auth.oauth.model;

import org.picketlink.auth.oauth.OAuthConstants;

public enum TokenEndpointAuthMethod {
    CLIENT_SECRET_BASIC(OAuthConstants.TOKEN_ENDPOINT_AUTH_BASIC),
    CLIENT_SECRET_POST(OAuthConstants.TOKEN_ENDPOINT_AUTH_POST);

    private final String value;

    TokenEndpointAuthMethod(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static TokenEndpointAuthMethod fromValue(String value) {
        if (value == null || value.isBlank()) {
            return CLIENT_SECRET_BASIC;
        }
        for (TokenEndpointAuthMethod method : values()) {
            if (method.value.equals(value)) {
                return method;
            }
        }
        throw new IllegalArgumentException("Unsupported token endpoint auth method: " + value);
    }
}
