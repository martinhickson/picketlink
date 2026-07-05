package org.picketlink.oidc.admin;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import org.picketlink.oidc.keystore.DynamicOidcKeyStore;
import org.picketlink.oidc.keystore.OidcKeyRotationResult;
import org.picketlink.oidc.keystore.ReloadableJwksService;

@Path("/keys")
@Produces(MediaType.APPLICATION_JSON)
public class OidcKeyAdminResource {

    private final DynamicOidcKeyStore keyStore;
    private final ReloadableJwksService jwksService;

    public OidcKeyAdminResource(DynamicOidcKeyStore keyStore, ReloadableJwksService jwksService) {
        this.keyStore = keyStore;
        this.jwksService = jwksService;
    }

    @GET
    public OidcKeyStatus status() throws Exception {
        return new OidcKeyStatus(
                keyStore.activeAlias(),
                keyStore.generation(),
                keyStore.keystorePath().toString(),
                keyStore.listKeys());
    }

    @POST
    @Path("/rotate")
    @Consumes(MediaType.WILDCARD)
    public OidcKeyRotationResult rotate(
            @QueryParam("validityDays") @DefaultValue("365") int validityDays) throws Exception {
        OidcKeyRotationResult result = keyStore.rotateSigningKey(validityDays);
        jwksService.invalidateCache();
        return result;
    }

    public record OidcKeyStatus(
            String activeAlias,
            long generation,
            String keystorePath,
            java.util.List<org.picketlink.oidc.keystore.OidcKeyInfo> keys) {
    }
}
