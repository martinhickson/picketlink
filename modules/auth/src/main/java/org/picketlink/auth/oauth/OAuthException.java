package org.picketlink.auth.oauth;

import org.picketlink.auth.oauth.model.OAuthErrorResponse;

public class OAuthException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final OAuthErrorResponse error;
    private final int httpStatus;

    public OAuthException(OAuthErrorResponse error, int httpStatus) {
        super(error.getError());
        this.error = error;
        this.httpStatus = httpStatus;
    }

    public OAuthErrorResponse getError() {
        return error;
    }

    public int getHttpStatus() {
        return httpStatus;
    }
}
