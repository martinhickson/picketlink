package org.picketlink.auth.oauth.rest;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.picketlink.auth.oauth.issuance.JwtIssuanceManager;

/** Serves the issuer's public signing keys as a JWKS document ({@code /.well-known/jwks.json}). */
@Path(".well-known/jwks.json")
public class JwksResource {

    private final JwtIssuanceManager issuanceManager;

    public JwksResource(JwtIssuanceManager issuanceManager) {
        this.issuanceManager = issuanceManager;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response jwks() {
        return Response.ok(issuanceManager.getSigningService().publicJwksJson()).build();
    }
}
