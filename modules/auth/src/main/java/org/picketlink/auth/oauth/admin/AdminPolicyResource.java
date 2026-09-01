package org.picketlink.auth.oauth.admin;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.picketlink.auth.oauth.store.IssuancePolicyConfig;
import org.picketlink.auth.oauth.store.IssuancePolicyStore;

/** Admin API for the issuance policy document. Protected by {@link AdminScopeFilter}. */
@Path("api/auth/admin/policies")
public class AdminPolicyResource {

    private final IssuancePolicyStore policyStore;

    public AdminPolicyResource(IssuancePolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response get() {
        return Response.ok(policyStore.load().toJson()).build();
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response update(String body) {
        IssuancePolicyConfig config = IssuancePolicyConfig.fromJson(body);
        if (!config.getAllowedAlgorithms().contains(config.getDefaultAlgorithm())) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"defaultAlgorithm must be in allowedAlgorithms\"}").build();
        }
        if (config.getMaxLifetimeSeconds() <= 0 || config.getDefaultLifetimeSeconds() <= 0
                || config.getDefaultLifetimeSeconds() > config.getMaxLifetimeSeconds()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"lifetimes must be positive and default <= max\"}").build();
        }
        policyStore.save(config);
        return Response.ok(config.toJson()).build();
    }
}
