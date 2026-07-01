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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.security.Principal;

/**
 * Returns HTTP 404 when admin JSON metadata is disabled; HTTP 401 when authentication is required but absent.
 */
public class AdminJsonMetadataPublishingFilter implements Filter {

    private static final Logger LOG = Logger.getLogger(AdminJsonMetadataPublishingFilter.class);

    private MetadataPublishingSettings settings;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        settings = MetadataPublishingFilterSupport.requireSettings(filterConfig.getServletContext());
        LOG.info("PicketLink admin JSON metadata gate installed for ["
                + MetadataPublishingConstants.ADMIN_JSON_METADATA_PATH + "] — "
                + describeState(settings));
        if (settings.isAdminJsonEnabled() && !settings.isAdminJsonRequireAuth()) {
            LOG.warn("PicketLink admin JSON metadata API is enabled WITHOUT authentication — "
                    + "set MetadataPublishing/@AdminJsonRequireAuth=\"true\" for production deployments");
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (!settings.isAdminJsonEnabled()) {
            httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        if (settings.isAdminJsonRequireAuth() && !isAuthenticated(httpRequest)) {
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        chain.doFilter(request, response);
    }

    private static boolean isAuthenticated(HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();
        if (principal != null) {
            return true;
        }
        String remoteUser = request.getRemoteUser();
        return remoteUser != null && !remoteUser.isEmpty();
    }

    private static String describeState(MetadataPublishingSettings settings) {
        if (!settings.isAdminJsonEnabled()) {
            return "DISABLED (HTTP 404)";
        }
        if (settings.isAdminJsonRequireAuth()) {
            return "ENABLED — authentication REQUIRED";
        }
        return "ENABLED — authentication OFF";
    }

    @Override
    public void destroy() {
    }
}
