package org.picketlink.auth.oauth.admin;

import java.util.List;
import java.util.Set;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.picketlink.auth.oauth.client.store.ClientRegistrationStore;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.token.AccessTokenGenerator;

/**
 * Admin API for REST clients: full CRUD over the registered client document (JSON in a CLOB or
 * file), including JWKS registration, audience pinning, auth method and secret rotation.
 * Protected by {@link AdminScopeFilter}.
 */
@Path("api/auth/admin/clients")
public class AdminClientResource {

    private static final String MASKED_SECRET = "********";

    private final ClientRegistrationStore store;

    public AdminClientResource(ClientRegistrationStore store) {
        this.store = store;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response list() {
        StringBuilder json = new StringBuilder("[");
        List<RegisteredClient> clients = store.findAll();
        for (int i = 0; i < clients.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            appendClient(json, clients.get(i));
        }
        json.append(']');
        return Response.ok(json.toString()).build();
    }

    @GET
    @Path("{clientId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response get(@PathParam("clientId") String clientId) {
        java.util.Optional<RegisteredClient> client = store.findByClientId(clientId);
        if (!client.isPresent()) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toJson(client.get())).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response create(String body) {
        JsonBody json = JsonBody.parse(body);
        String clientId = json.string("clientId");
        if (clientId == null || clientId.isBlank()) {
            return badRequest("clientId is required");
        }
        if (store.findByClientId(clientId).isPresent()) {
            return Response.status(Response.Status.CONFLICT)
                    .entity("{\"error\":\"client already exists\"}").build();
        }
        String secret = json.string("clientSecret");
        boolean generated = false;
        if (secret == null) {
            secret = new AccessTokenGenerator(32).generate();
            generated = true;
        }
        RegisteredClient client = buildClient(json, clientId, secret);
        store.save(client);
        String view = toJson(client);
        if (generated) {
            view = view.replace("\"" + MASKED_SECRET + "\"",
                    "\"" + OAuthJsonWriter.escape(secret) + "\"");
        }
        return Response.status(Response.Status.CREATED).entity(view).build();
    }

    @PUT
    @Path("{clientId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response update(@PathParam("clientId") String clientId, String body) {
        if (!store.findByClientId(clientId).isPresent()) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        JsonBody json = JsonBody.parse(body);
        String secret = json.string("clientSecret");
        if (secret == null) {
            RegisteredClient existing = store.findByClientId(clientId).get();
            secret = existing.getClientSecret();
        }
        RegisteredClient client = buildClient(json, clientId, secret);
        store.save(client);
        return Response.ok(toJson(client)).build();
    }

    @POST
    @Path("{clientId}/rotate-secret")
    @Produces(MediaType.APPLICATION_JSON)
    public Response rotateSecret(@PathParam("clientId") String clientId) {
        java.util.Optional<RegisteredClient> existing = store.findByClientId(clientId);
        if (!existing.isPresent()) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        RegisteredClient client = existing.get();
        if (client.getClientSecret() == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"client does not use a static secret\"}").build();
        }
        String newSecret = new AccessTokenGenerator(32).generate();
        store.save(RegisteredClient.builder(client.getClientId(), newSecret)
                .scopes(client.getScopes())
                .tokenEndpointAuthMethod(client.getTokenEndpointAuthMethod())
                .allowedAudiences(client.getAllowedAudiences())
                .jwks(client.getJwks())
                .maxTokenLifetimeSeconds(client.getMaxTokenLifetimeSeconds())
                .build());
        return Response.ok("{\"clientSecret\":\"" + OAuthJsonWriter.escape(newSecret) + "\"}").build();
    }

    @DELETE
    @Path("{clientId}")
    public Response delete(@PathParam("clientId") String clientId) {
        return store.delete(clientId)
                ? Response.noContent().build()
                : Response.status(Response.Status.NOT_FOUND).build();
    }

    private static RegisteredClient buildClient(JsonBody json, String clientId, String secret) {
        RegisteredClient.Builder builder = RegisteredClient.builder(clientId, secret);
        builder.scopes(json.array("scopes"));
        String authMethod = json.string("tokenEndpointAuthMethod");
        if (authMethod != null) {
            builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.fromValue(authMethod));
        }
        Set<String> audiences = json.array("allowedAudiences");
        if (!audiences.isEmpty()) {
            builder.allowedAudiences(audiences);
        }
        String jwks = json.string("jwks");
        if (jwks != null) {
            builder.jwks(jwks);
        }
        long maxLifetime = json.number("maxTokenLifetimeSeconds", 0L);
        if (maxLifetime > 0) {
            builder.maxTokenLifetimeSeconds(maxLifetime);
        }
        return builder.build();
    }

    private static String toJson(RegisteredClient client) {
        StringBuilder json = new StringBuilder();
        json.append('[');
        appendClient(json, client);
        json.append(']');
        return json.substring(1, json.length() - 1);
    }

    private static void appendClient(StringBuilder json, RegisteredClient client) {
        json.append('{');
        json.append("\"clientId\":\"").append(OAuthJsonWriter.escape(client.getClientId())).append('"');
        json.append(",\"clientSecret\":\"")
                .append(client.getClientSecret() == null ? "" : MASKED_SECRET).append('"');
        json.append(",\"scopes\":[");
        int i = 0;
        for (String scope : client.getScopes()) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(OAuthJsonWriter.escape(scope)).append('"');
            i++;
        }
        json.append(']');
        json.append(",\"tokenEndpointAuthMethod\":\"")
                .append(client.getTokenEndpointAuthMethod().getValue()).append('"');
        json.append(",\"allowedAudiences\":[");
        i = 0;
        for (String audience : client.getAllowedAudiences()) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(OAuthJsonWriter.escape(audience)).append('"');
            i++;
        }
        json.append(']');
        json.append(",\"hasJwks\":").append(client.getJwks() != null);
        json.append(",\"maxTokenLifetimeSeconds\":").append(client.getMaxTokenLifetimeSeconds());
        json.append('}');
    }

    private static Response badRequest(String description) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity("{\"error\":\"" + OAuthJsonWriter.escape(description) + "\"}").build();
    }
}
