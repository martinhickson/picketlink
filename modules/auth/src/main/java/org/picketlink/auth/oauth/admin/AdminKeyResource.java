package org.picketlink.auth.oauth.admin;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.picketlink.auth.oauth.store.SigningKeyDocument;
import org.picketlink.auth.oauth.store.SigningKeyStore;

/**
 * Admin API for signing keys: list metadata, rotate (new keypair into the keystore, old key
 * stays verifiable in the overlap window) and activate an existing key (rollback).
 * Protected by {@link AdminScopeFilter}.
 */
@Path("api/auth/admin/keys")
public class AdminKeyResource {

    private final SigningKeyStore keyStore;

    public AdminKeyResource(SigningKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response list() {
        return Response.ok(keyStore.loadDocument().toJson()).build();
    }

    @POST
    @Path("rotate")
    @Produces(MediaType.APPLICATION_JSON)
    public Response rotate() {
        try {
            String keyId = keyStore.rotate();
            SigningKeyDocument document = keyStore.loadDocument();
            return Response.ok("{\"activeKid\":\"" + keyId + "\",\"keys\":"
                    + keysJson(document) + "}").build();
        } catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"key rotation failed: " + ex.getMessage() + "\"}").build();
        }
    }

    @PUT
    @Path("{keyId}/activate")
    public Response activate(@PathParam("keyId") String keyId) {
        try {
            keyStore.activate(keyId);
            return Response.noContent().build();
        } catch (IllegalArgumentException ex) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    private static String keysJson(SigningKeyDocument document) {
        String json = document.toJson();
        int keysIndex = json.indexOf("\"keys\"");
        return json.substring(keysIndex);
    }
}
