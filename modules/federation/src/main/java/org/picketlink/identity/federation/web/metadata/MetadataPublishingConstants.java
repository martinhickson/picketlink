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

/**
 * Paths and servlet-context attribute names for metadata publishing.
 */
public final class MetadataPublishingConstants {

    public static final String XML_METADATA_PATH = "/metadata";

    public static final String ADMIN_JSON_METADATA_PATH = "/api/admin/federation/metadata";

    public static final String SETTINGS_CONTEXT_ATTRIBUTE =
            "org.picketlink.identity.federation.metadata.publishing.settings";

    public static final String CONFIG_FILE_CONTEXT_ATTRIBUTE =
            "org.picketlink.identity.federation.metadata.publishing.configFile";

    public static final String XML_GATE_FILTER_NAME = "PicketLinkXmlMetadataPublishingFilter";

    public static final String ADMIN_JSON_GATE_FILTER_NAME = "PicketLinkAdminJsonMetadataPublishingFilter";

    public static final String ADMIN_JSON_SERVLET_NAME = "PicketLinkAdminMetadataJsonServlet";

    private MetadataPublishingConstants() {
    }
}
