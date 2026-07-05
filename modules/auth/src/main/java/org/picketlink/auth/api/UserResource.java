package org.picketlink.auth.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import java.util.LinkedHashMap;
import java.util.Map;
import org.picketlink.auth.oauth.jwt.JwtClaims;

@Path("user")
public class UserResource {

    @Context
    private HttpServletRequest request;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> getUser() {
        JwtClaims claims = (JwtClaims) request.getAttribute(JwtClaims.class.getName());
        Map<String, String> payload = new LinkedHashMap<String, String>();
        payload.put("clientId", claims == null ? "" : claims.getClientId());
        if (claims != null && claims.getScope() != null) {
            payload.put("scope", claims.getScope());
        }
        return payload;
    }
}
