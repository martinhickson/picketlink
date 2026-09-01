package org.picketlink.auth.oauth.rest;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.picketlink.auth.oauth.service.TokenIntrospectionService;

/** RFC 7662 token introspection endpoint ({@code /introspect}). */
@Path("introspect")
public class TokenIntrospectionResource {

    private final TokenIntrospectionService introspectionService;

    public TokenIntrospectionResource(TokenIntrospectionService introspectionService) {
        this.introspectionService = introspectionService;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspect(MultivaluedMap<String, String> form,
            @jakarta.ws.rs.HeaderParam("Authorization") String authorization) {
        try {
            return Response.ok(introspectionService.introspect(
                    TokenRevocationResource.toTokenRequest(form, authorization))).build();
        } catch (org.picketlink.auth.oauth.OAuthException ex) {
            return Response.status(ex.getHttpStatus())
                    .entity(org.picketlink.auth.oauth.json.OAuthJsonWriter
                            .writeErrorResponse(ex.getError()))
                    .build();
        }
    }
}
