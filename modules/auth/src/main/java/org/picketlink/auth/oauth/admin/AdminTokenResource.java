package org.picketlink.auth.oauth.admin;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.picketlink.auth.oauth.store.JdbcAccessTokenRegistry;

/**
 * Admin API for issued tokens: browse (hashes only, never raw JWTs) and revoke by hash.
 * Only available with the JDBC token registry. Protected by {@link AdminScopeFilter}.
 */
@Path("api/auth/admin/tokens")
public class AdminTokenResource {

    private final JdbcAccessTokenRegistry tokenRegistry;

    public AdminTokenResource(JdbcAccessTokenRegistry tokenRegistry) {
        this.tokenRegistry = tokenRegistry;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response list(@QueryParam("limit") @DefaultValue("100") int limit) {
        StringBuilder json = new StringBuilder("[");
        java.util.List<JdbcAccessTokenRegistry.TokenRecordView> records = tokenRegistry.list(limit);
        for (int i = 0; i < records.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(records.get(i).toJson());
        }
        json.append(']');
        return Response.ok(json.toString()).build();
    }

    @DELETE
    @Path("{tokenHash}")
    public Response revoke(@PathParam("tokenHash") String tokenHash) {
        return tokenRegistry.removeByTokenHash(tokenHash)
                ? Response.noContent().build()
                : Response.status(Response.Status.NOT_FOUND).build();
    }
}
