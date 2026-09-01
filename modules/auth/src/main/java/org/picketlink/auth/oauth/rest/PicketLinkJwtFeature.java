package org.picketlink.auth.oauth.rest;

import jakarta.ws.rs.core.Feature;
import jakarta.ws.rs.core.FeatureContext;
import jakarta.ws.rs.ext.Provider;

import org.picketlink.auth.oauth.issuance.JwtIssuanceManager;

/**
 * Registers JWT bearer protection on any JAX-RS application: {@code new PicketLinkJwtFeature(manager)}.
 * Works with CXF, RESTEasy or any Jakarta implementation without running a full identity provider.
 */
@Provider
public class PicketLinkJwtFeature implements Feature {

    private final JwtIssuanceManager issuanceManager;

    public PicketLinkJwtFeature(JwtIssuanceManager issuanceManager) {
        this.issuanceManager = issuanceManager;
    }

    @Override
    public boolean configure(FeatureContext context) {
        context.register(new JwtBearerAuthenticationFilter(issuanceManager));
        return true;
    }
}
