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

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;

/**
 * Shared filter bootstrap helpers.
 */
final class MetadataPublishingFilterSupport {

    private MetadataPublishingFilterSupport() {
    }

    static MetadataPublishingSettings requireSettings(ServletContext servletContext) throws ServletException {
        Object value = servletContext.getAttribute(MetadataPublishingConstants.SETTINGS_CONTEXT_ATTRIBUTE);
        if (value instanceof MetadataPublishingSettings) {
            return (MetadataPublishingSettings) value;
        }
        throw new ServletException("PicketLink metadata publishing settings are missing from servlet context — "
                + "metadata gate filters were not installed correctly");
    }
}
