package org.picketlink.auth.oauth;

public final class OAuthConstants {

    public static final String GRANT_TYPE = "grant_type";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String SCOPE = "scope";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String TOKEN_TYPE = "token_type";
    public static final String EXPIRES_IN = "expires_in";
    public static final String ERROR = "error";
    public static final String ERROR_DESCRIPTION = "error_description";

    public static final String CLIENT_CREDENTIALS_GRANT = "client_credentials";
    public static final String BEARER_TOKEN_TYPE = "Bearer";

    public static final String TOKEN_ENDPOINT_AUTH_BASIC = "client_secret_basic";
    public static final String TOKEN_ENDPOINT_AUTH_POST = "client_secret_post";

    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String INVALID_SCOPE = "invalid_scope";

    public static final String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
    public static final String APPLICATION_JSON = "application/json";

    private OAuthConstants() {
    }
}
