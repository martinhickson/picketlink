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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.logging.Logger;

import java.io.IOException;

/**
 * Returns HTTP 404 when SAML XML metadata publishing is disabled by configuration.
 */
public class XmlMetadataPublishingFilter implements Filter {

    private static final Logger LOG = Logger.getLogger(XmlMetadataPublishingFilter.class);

    private MetadataPublishingSettings settings;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        settings = MetadataPublishingFilterSupport.requireSettings(filterConfig.getServletContext());
        LOG.info("PicketLink XML metadata gate installed for [" + MetadataPublishingConstants.XML_METADATA_PATH + "] — "
                + (settings.isXmlEnabled() ? "ENABLED" : "DISABLED (HTTP 404)"));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!settings.isXmlEnabled()) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }
}
