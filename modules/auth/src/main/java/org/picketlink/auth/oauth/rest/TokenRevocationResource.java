package org.picketlink.auth.oauth.rest;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.service.TokenRevocationService;
import org.picketlink.auth.oauth.model.TokenRequest;

/** RFC 7009 token revocation endpoint ({@code /revoke}). */
@Path("revoke")
public class TokenRevocationResource {

    private final TokenRevocationService revocationService;

    public TokenRevocationResource(TokenRevocationService revocationService) {
        this.revocationService = revocationService;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response revoke(MultivaluedMap<String, String> form,
            @jakarta.ws.rs.HeaderParam("Authorization") String authorization) {
        try {
            revocationService.revoke(toTokenRequest(form, authorization));
            return Response.ok().build();
        } catch (org.picketlink.auth.oauth.OAuthException ex) {
            return Response.status(ex.getHttpStatus())
                    .entity(org.picketlink.auth.oauth.json.OAuthJsonWriter
                            .writeErrorResponse(ex.getError()))
                    .build();
        }
    }

    static TokenRequest toTokenRequest(MultivaluedMap<String, String> form, String authorization) {
        TokenRequest.Builder builder = TokenRequest.builder()
                .authorizationHeader(authorization)
                .grantType(form.getFirst(OAuthConstants.GRANT_TYPE));
        for (String name : form.keySet()) {
            builder.formParameter(name, form.getFirst(name));
        }
        return builder.build();
    }
}
