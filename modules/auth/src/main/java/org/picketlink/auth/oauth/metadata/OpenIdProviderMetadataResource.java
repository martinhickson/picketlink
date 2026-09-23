package org.picketlink.auth.oauth.metadata;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import org.picketlink.auth.oauth.OAuthConstants;

@Path(".well-known/openid-configuration")
public class OpenIdProviderMetadataResource {

    private final OAuthAuthorizationServerMetadataResource document;

    public OpenIdProviderMetadataResource(OAuthAuthorizationServerMetadata metadata) {
        this.document = new OAuthAuthorizationServerMetadataResource(metadata);
    }

    @GET
    @Produces(OAuthConstants.APPLICATION_JSON)
    public String metadataDocument() {
        return document.metadataDocument();
    }
}
