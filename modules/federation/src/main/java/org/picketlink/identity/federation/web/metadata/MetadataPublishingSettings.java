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

import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.MetadataPublishingType;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.config.federation.SPType;

/**
 * Resolved metadata publishing switches with PicketLink defaults applied.
 */
public final class MetadataPublishingSettings {

    private final boolean xmlEnabled;
    private final boolean adminJsonEnabled;
    private final boolean adminJsonRequireAuth;
    private final String federationRole;

    private MetadataPublishingSettings(boolean xmlEnabled, boolean adminJsonEnabled,
            boolean adminJsonRequireAuth, String federationRole) {
        this.xmlEnabled = xmlEnabled;
        this.adminJsonEnabled = adminJsonEnabled;
        this.adminJsonRequireAuth = adminJsonRequireAuth;
        this.federationRole = federationRole;
    }

    public static MetadataPublishingSettings fromProvider(ProviderType providerType) {
        MetadataPublishingType publishing = providerType != null ? providerType.getMetadataPublishing() : null;
        boolean xmlEnabled = publishing == null || publishing.isXmlEnabled();
        boolean adminJsonEnabled = publishing != null && publishing.isAdminJsonEnabled();
        boolean adminJsonRequireAuth = publishing == null || publishing.isAdminJsonRequireAuth();
        String role = resolveRole(providerType);
        return new MetadataPublishingSettings(xmlEnabled, adminJsonEnabled, adminJsonRequireAuth, role);
    }

    private static String resolveRole(ProviderType providerType) {
        if (providerType instanceof IDPType) {
            return "SAML Identity Provider (IDP)";
        }
        if (providerType instanceof SPType) {
            return "SAML Service Provider (SP)";
        }
        return "SAML Federation";
    }

    public boolean isXmlEnabled() {
        return xmlEnabled;
    }

    public boolean isAdminJsonEnabled() {
        return adminJsonEnabled;
    }

    public boolean isAdminJsonRequireAuth() {
        return adminJsonRequireAuth;
    }

    public String getFederationRole() {
        return federationRole;
    }
}
