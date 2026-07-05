package org.picketlink.auth.oauth.metadata;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;

@Path(".well-known/oauth-authorization-server")
public class OAuthAuthorizationServerMetadataResource {

    private final OAuthAuthorizationServerMetadata metadata;

    public OAuthAuthorizationServerMetadataResource(OAuthAuthorizationServerMetadata metadata) {
        this.metadata = metadata;
    }

    @GET
    @Produces(OAuthConstants.APPLICATION_JSON)
    public String metadataDocument() {
        StringBuilder json = new StringBuilder();
        json.append('{');
        append(json, "issuer", metadata.getIssuer(), true);
        append(json, "token_endpoint", metadata.getTokenEndpoint(), false);
        appendArray(json, "grant_types_supported", metadata.getGrantTypesSupported(), false);
        appendArray(json, "token_endpoint_auth_methods_supported",
                metadata.getTokenEndpointAuthMethodsSupported(), false);
        if (!metadata.getScopesSupported().isEmpty()) {
            appendArray(json, "scopes_supported", metadata.getScopesSupported(), false);
        }
        json.append('}');
        return json.toString();
    }

    private static void append(StringBuilder json, String name, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":\"")
                .append(OAuthJsonWriter.escape(value)).append('"');
    }

    private static void appendArray(StringBuilder json, String name, java.util.List<String> values, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(OAuthJsonWriter.escape(values.get(i))).append('"');
        }
        json.append(']');
    }
}
