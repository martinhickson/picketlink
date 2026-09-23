package org.picketlink.auth.oauth.metadata;

import java.util.Collections;
import java.util.List;
import org.picketlink.auth.oauth.OAuthConstants;

public final class OAuthAuthorizationServerMetadata {

    private final String issuer;
    private final String tokenEndpoint;
    private final String authorizationEndpoint;
    private final String jwksUri;
    private final List<String> grantTypesSupported;
    private final List<String> tokenEndpointAuthMethodsSupported;
    private final List<String> scopesSupported;
    private final List<String> idTokenSigningAlgValuesSupported;

    public OAuthAuthorizationServerMetadata(String issuer, String tokenEndpoint,
            List<String> scopesSupported) {
        this(issuer, tokenEndpoint, null, null, List.of(OAuthConstants.CLIENT_CREDENTIALS_GRANT),
                scopesSupported, List.of());
    }

    public OAuthAuthorizationServerMetadata(String issuer, String tokenEndpoint, String authorizationEndpoint,
            String jwksUri, List<String> grantTypesSupported, List<String> scopesSupported,
            List<String> idTokenSigningAlgValuesSupported) {
        this.issuer = issuer;
        this.tokenEndpoint = tokenEndpoint;
        this.authorizationEndpoint = authorizationEndpoint;
        this.jwksUri = jwksUri;
        this.grantTypesSupported = grantTypesSupported == null
                ? List.of(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                : List.copyOf(grantTypesSupported);
        this.scopesSupported = scopesSupported == null
                ? Collections.emptyList()
                : List.copyOf(scopesSupported);
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported == null
                ? List.of()
                : List.copyOf(idTokenSigningAlgValuesSupported);
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

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public String getJwksUri() {
        return jwksUri;
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

    public List<String> getIdTokenSigningAlgValuesSupported() {
        return idTokenSigningAlgValuesSupported;
    }
}
