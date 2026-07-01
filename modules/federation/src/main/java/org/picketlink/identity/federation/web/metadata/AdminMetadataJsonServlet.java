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
package org.picketlink.identity.federation.web.metadata;

import org.jboss.logging.Logger;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Admin portal JSON view of SAML entity metadata. Access is gated by {@link AdminJsonMetadataPublishingFilter}.
 */
public class AdminMetadataJsonServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG = Logger.getLogger(AdminMetadataJsonServlet.class);

    private transient EntityDescriptorType metadata;
    private transient String federationRole;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            String configFile = (String) config.getServletContext()
                    .getAttribute(MetadataPublishingConstants.CONFIG_FILE_CONTEXT_ATTRIBUTE);
            if (configFile == null) {
                configFile = config.getInitParameter("configFile");
            }
            if (configFile == null) {
                throw new ServletException("Metadata configuration file location is not set");
            }
            MetadataPublishingLoader.LoadedMetadata loaded =
                    MetadataPublishingLoader.load(config.getServletContext(), configFile);
            this.metadata = loaded.getEntityDescriptor();
            this.federationRole = loaded.getRole();
            LOG.info("PicketLink admin JSON metadata servlet initialized for entity ["
                    + metadata.getEntityID() + "] role [" + federationRole + "]");
        } catch (Exception e) {
            LOG.error("Failed to initialize PicketLink admin JSON metadata servlet", e);
            throw new ServletException("Unable to initialize admin metadata JSON servlet", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        PrintWriter writer = resp.getWriter();
        writer.write(MetadataJsonWriter.toJson(metadata, federationRole));
        writer.flush();
    }
}
