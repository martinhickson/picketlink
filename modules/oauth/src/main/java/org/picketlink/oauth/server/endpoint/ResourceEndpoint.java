/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.picketlink.oauth.server.endpoint;

import org.picketlink.oauth.messages.ErrorResponse;
import org.picketlink.oauth.messages.ErrorResponse.ErrorResponseCode;
import org.picketlink.oauth.messages.ResourceAccessRequest;
import org.picketlink.oauth.server.util.OAuthServerUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import java.net.URISyntaxException;

/**
 * OAuth2 Resource Endpoint
 *
 * @author anil saldhana
 * @since Aug 27, 2012
 */
@Path("/resource")
public class ResourceEndpoint extends BaseEndpoint {
    private static final long serialVersionUID = 1L;

    @POST
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/html")
    public Response authorize(@Context HttpServletRequest request) throws URISyntaxException {
        super.setup();

        ResourceAccessRequest resourceAccessRequest = OAuthServerUtil.parseResourceRequest(request);
        String accessToken = resourceAccessRequest.getAccessToken();
        boolean validateAccessToken = OAuthServerUtil.validateAccessToken(accessToken, identityManager);

        // TODO: Deal with scope
        if (validateAccessToken) {
            return Response.ok().entity("I am a Resource").build();
        } else {
            ErrorResponse errorResponse = new ErrorResponse();
            errorResponse.setStatusCode(HttpServletResponse.SC_BAD_REQUEST);
            errorResponse.setError(ErrorResponseCode.invalid_client).setErrorDescription("accessToken not found");
            return Response.status(errorResponse.getStatusCode()).entity(errorResponse.asJSON()).build();
        }
    }
}