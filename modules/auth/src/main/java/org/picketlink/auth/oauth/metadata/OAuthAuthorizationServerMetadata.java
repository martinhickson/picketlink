package org.picketlink.auth.oauth.metadata;

import java.util.Collections;
import java.util.List;
import org.picketlink.auth.oauth.OAuthConstants;

public final class OAuthAuthorizationServerMetadata {

    private final String issuer;
    private final String tokenEndpoint;
    private final List<String> grantTypesSupported;
    private final List<String> tokenEndpointAuthMethodsSupported;
    private final List<String> scopesSupported;

    public OAuthAuthorizationServerMetadata(String issuer, String tokenEndpoint,
            List<String> scopesSupported) {
        this.issuer = issuer;
        this.tokenEndpoint = tokenEndpoint;
        this.scopesSupported = scopesSupported == null
                ? Collections.emptyList()
                : List.copyOf(scopesSupported);
        this.grantTypesSupported = List.of(OAuthConstants.CLIENT_CREDENTIALS_GRANT);
        this.tokenEndpointAuthMethodsSupported = List.of(
                OAuthConstants.TOKEN_ENDPOINT_AUTH_BASIC,
                OAuthConstants.TOKEN_ENDPOINT_AUTH_POST);
    }

    public String getIssuer() {
        return issuer;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public List<String> getGrantTypesSupported() {
        return grantTypesSupported;
    }

    public List<String> getTokenEndpointAuthMethodsSupported() {
        return tokenEndpointAuthMethodsSupported;
    }

    public List<String> getScopesSupported() {
        return scopesSupported;
    }
}
