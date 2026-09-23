package org.picketlink.auth.oauth.grant;

import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;

public interface GrantHandler {

    String grantType();

    TokenResponse issue(TokenRequest request);
}
