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

/**
 * User-friendly INFO logging for metadata publishing configuration at deployment time.
 */
public final class MetadataPublishingStartupLog {

    private static final Logger LOG = Logger.getLogger(MetadataPublishingStartupLog.class);

    private MetadataPublishingStartupLog() {
    }

    public static void logDeploymentSummary(String deploymentName, String contextPath,
            MetadataPublishingSettings settings) {
        String basePath = normalizeContextPath(contextPath);
        String xmlUrl = basePath + MetadataPublishingConstants.XML_METADATA_PATH;
        String jsonUrl = basePath + MetadataPublishingConstants.ADMIN_JSON_METADATA_PATH;

        LOG.info("");
        LOG.info("========== PicketLink Metadata Publishing ==========");
        LOG.info("Deployment : " + deploymentName);
        LOG.info("Role       : " + settings.getFederationRole());
        LOG.info("Context    : " + basePath);
        LOG.info("----------------------------------------------------");
        logSwitch("XML metadata (SAML partners)", settings.isXmlEnabled(), xmlUrl,
                settings.isXmlEnabled() ? "GET — application/samlmetadata+xml" : "DISABLED — requests receive HTTP 404");
        logSwitch("Admin JSON metadata (portal UI)", settings.isAdminJsonEnabled(), jsonUrl,
                describeAdminJsonBehavior(settings));
        if (settings.isAdminJsonEnabled()) {
            if (settings.isAdminJsonRequireAuth()) {
                LOG.info("  Admin JSON authentication : REQUIRED (unauthenticated requests receive HTTP 401)");
            } else {
                LOG.warn("  Admin JSON authentication : OFF — metadata JSON is anonymously readable (not recommended for production)");
            }
        } else {
            LOG.info("  Admin JSON authentication : n/a (admin JSON API is disabled)");
        }
        LOG.info("Config switches:");
        LOG.info("  MetadataPublishing/@XmlEnabled           = " + settings.isXmlEnabled());
        LOG.info("  MetadataPublishing/@AdminJsonEnabled     = " + settings.isAdminJsonEnabled());
        LOG.info("  MetadataPublishing/@AdminJsonRequireAuth = "
                + (settings.isAdminJsonEnabled() ? settings.isAdminJsonRequireAuth() : "n/a"));
        LOG.info("====================================================");
        LOG.info("");
    }

    private static void logSwitch(String label, boolean enabled, String url, String behavior) {
        LOG.info("  " + label + " : " + (enabled ? "ON" : "OFF"));
        LOG.info("    URL      : " + url);
        LOG.info("    Behavior : " + behavior);
    }

    private static String describeAdminJsonBehavior(MetadataPublishingSettings settings) {
        if (!settings.isAdminJsonEnabled()) {
            return "DISABLED — requests receive HTTP 404 (default; enable with AdminJsonEnabled=\"true\")";
        }
        return "GET — application/json";
    }

    private static String normalizeContextPath(String contextPath) {
        if (contextPath == null || contextPath.isEmpty() || "/".equals(contextPath)) {
            return "";
        }
        return contextPath.endsWith("/") ? contextPath.substring(0, contextPath.length() - 1) : contextPath;
    }
}
