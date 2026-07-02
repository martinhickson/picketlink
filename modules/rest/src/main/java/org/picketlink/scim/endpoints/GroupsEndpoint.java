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
package org.picketlink.scim.endpoints;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.picketlink.scim.DataProvider;
import org.picketlink.scim.codec.SCIMParser;
import org.picketlink.scim.codec.SCIMWriter;
import org.picketlink.scim.codec.SCIMWriterException;
import org.picketlink.scim.model.v11.SCIMGroups;

/**
 * REST Endpoint for Groups
 *
 * @author anil saldhana
 * @since Apr 9, 2013
 */
@Path("/Groups")
public class GroupsEndpoint extends AbstractSCIMEndpoint {
    private static Logger log = Logger.getLogger(UsersEndpoint.class);

    @GET
    @Path("{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@Context HttpServletRequest request, @Context ServletContext sc, @PathParam("id") String groupId) {
        resolveDataProvider(sc);
        try {
            dataProvider.initializeConnection();
            SCIMGroups group = dataProvider.getGroups(groupId);
            SCIMWriter writer = new SCIMWriter();

            String json = "";
            try {
                json = writer.json(group);
            } catch (SCIMWriterException e) {
                throw new RuntimeException(e);
            }
            return Response.status(200).entity(json).build();
        } finally {
            dataProvider.closeConnection();
        }
    }

    // Create a group
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response createGroup(@Context HttpServletRequest request, @Context ServletContext sc) {
        resolveDataProvider(sc);
        try {
            // Parse the data
            SCIMParser parser = new SCIMParser();
            SCIMGroups group = null;
            try {
                group = parser.parseGroup(request.getInputStream());
            } catch (Exception e1) {
                throw new RuntimeException(e1);
            }

            dataProvider.initializeConnection();
            String id = dataProvider.createGroup(group);

            group.setId(id);

            SCIMWriter writer = new SCIMWriter();

            String json = "";
            try {
                json = writer.json(group);
            } catch (SCIMWriterException e) {
                throw new RuntimeException(e);
            }
            return Response.status(200).entity(json).build();
        } finally {
            dataProvider.closeConnection();
        }
    }
}