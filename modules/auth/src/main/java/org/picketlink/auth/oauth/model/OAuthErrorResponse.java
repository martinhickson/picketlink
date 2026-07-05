package org.picketlink.auth.oauth.model;

public final class OAuthErrorResponse {

    private final String error;
    private final String errorDescription;

    public OAuthErrorResponse(String error) {
        this(error, null);
    }

    public OAuthErrorResponse(String error, String errorDescription) {
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}
