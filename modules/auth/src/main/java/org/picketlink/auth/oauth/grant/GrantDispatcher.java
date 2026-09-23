package org.picketlink.auth.oauth.grant;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;

public final class GrantDispatcher {

    private final Map<String, GrantHandler> handlers;

    public GrantDispatcher(List<GrantHandler> handlers) {
        Map<String, GrantHandler> mapped = new LinkedHashMap<>();
        for (GrantHandler handler : handlers) {
            mapped.put(handler.grantType(), handler);
        }
        this.handlers = Map.copyOf(mapped);
    }

    public List<String> grantTypes() {
        return new ArrayList<>(handlers.keySet());
    }

    public TokenResponse issue(TokenRequest request) {
        String grantType = request.getGrantType();
        if (grantType == null || grantType.isBlank()) {
            throw new OAuthException(
                    new OAuthErrorResponse(OAuthConstants.INVALID_REQUEST, "grant_type is required"),
                    400);
        }
        GrantHandler handler = handlers.get(grantType);
        if (handler == null) {
            throw new OAuthException(
                    new OAuthErrorResponse(OAuthConstants.UNSUPPORTED_GRANT_TYPE,
                            "grant_type is not supported"),
                    400);
        }
        return handler.issue(request);
    }
}
