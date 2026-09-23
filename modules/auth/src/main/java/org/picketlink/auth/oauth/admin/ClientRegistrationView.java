package org.picketlink.auth.oauth.admin;

import java.util.ArrayList;
import java.util.List;

public class ClientRegistrationView {

    private String clientId;
    private String clientSecret;
    private List<String> scopes = new ArrayList<String>();
    private List<String> allowedRedirectUris = new ArrayList<String>();
    private String tokenEndpointAuthMethod;
    private String backchannelLogoutUrl;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public String getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public List<String> getAllowedRedirectUris() {
        return allowedRedirectUris;
    }

    public void setAllowedRedirectUris(List<String> allowedRedirectUris) {
        this.allowedRedirectUris = allowedRedirectUris;
    }

    public String getBackchannelLogoutUrl() {
        return backchannelLogoutUrl;
    }

    public void setBackchannelLogoutUrl(String backchannelLogoutUrl) {
        this.backchannelLogoutUrl = backchannelLogoutUrl;
    }
}
