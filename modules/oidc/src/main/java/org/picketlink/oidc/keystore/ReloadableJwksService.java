package org.picketlink.oidc.keystore;

import java.lang.reflect.Field;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.cxf.rs.security.oidc.idp.OidcKeysService;

/**
 * JWKS endpoint that can be refreshed after keystore rotation.
 */
@Path("jwks")
public final class ReloadableJwksService extends OidcKeysService {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Override
    public JsonWebKeys getPublicVerificationKeys() {
        return super.getPublicVerificationKeys();
    }

    public void invalidateCache() {
        try {
            Field cache = OidcKeysService.class.getDeclaredField("keySet");
            cache.setAccessible(true);
            cache.set(this, null);
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException("Unable to invalidate JWKS cache", ex);
        }
    }
}
