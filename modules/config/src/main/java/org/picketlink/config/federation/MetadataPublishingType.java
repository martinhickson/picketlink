/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * you may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.picketlink.config.federation;

/**
 * Controls SAML XML metadata and admin JSON metadata publishing endpoints.
 */
public class MetadataPublishingType {

    private Boolean xmlEnabled;

    private Boolean adminJsonEnabled;

    private Boolean adminJsonRequireAuth;

    /**
     * SAML federation metadata XML ({@code /metadata}). Default {@code true}.
     */
    public boolean isXmlEnabled() {
        return xmlEnabled == null || xmlEnabled;
    }

    public void setXmlEnabled(Boolean xmlEnabled) {
        this.xmlEnabled = xmlEnabled;
    }

    /**
     * Admin portal JSON metadata API. Default {@code false}.
     */
    public boolean isAdminJsonEnabled() {
        return adminJsonEnabled != null && adminJsonEnabled;
    }

    public void setAdminJsonEnabled(Boolean adminJsonEnabled) {
        this.adminJsonEnabled = adminJsonEnabled;
    }

    /**
     * When admin JSON is enabled, require an authenticated user. Default {@code true}.
     */
    public boolean isAdminJsonRequireAuth() {
        return adminJsonRequireAuth == null || adminJsonRequireAuth;
    }

    public void setAdminJsonRequireAuth(Boolean adminJsonRequireAuth) {
        this.adminJsonRequireAuth = adminJsonRequireAuth;
    }
}
