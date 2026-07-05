package org.picketlink.auth.api;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.LinkedHashMap;
import java.util.Map;

@Path("version")
public class VersionResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> getVersion() {
        Map<String, String> payload = new LinkedHashMap<String, String>();
        payload.put("version", "1.0.0");
        return payload;
    }
}
