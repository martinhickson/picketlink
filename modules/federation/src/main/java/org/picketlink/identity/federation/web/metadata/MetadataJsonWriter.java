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

import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.IDPSSODescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.IndexedEndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyTypes;
import org.picketlink.identity.federation.saml.v2.metadata.SPSSODescriptorType;

import java.net.URI;
import java.util.List;

/**
 * Builds admin-friendly JSON from SAML entity metadata (no external JSON library required).
 */
public final class MetadataJsonWriter {

    private MetadataJsonWriter() {
    }

    public static String toJson(EntityDescriptorType entity, String role) {
        StringBuilder json = new StringBuilder(512);
        json.append('{');
        field(json, "entityId", entity.getEntityID());
        json.append(',');
        field(json, "role", role);
        json.append(',');
        append(json, "signed", entity.getSignature() != null);

        if ("IDP".equals(role)) {
            appendIdp(json, entity);
        } else if ("SP".equals(role)) {
            appendSp(json, entity);
        }

        json.append('}');
        return json.toString();
    }

    private static void appendIdp(StringBuilder json, EntityDescriptorType entity) {
        IDPSSODescriptorType idp = CoreConfigUtil.getIDPDescriptor(entity);
        if (idp == null) {
            return;
        }
        json.append(',');
        append(json, "wantAuthnRequestsSigned", idp.isWantAuthnRequestsSigned());
        json.append(',');
        appendEndpoints(json, "singleSignOnServices", idp.getSingleSignOnService());
        json.append(',');
        appendEndpoints(json, "singleLogoutServices", idp.getSingleLogoutService());
        json.append(',');
        appendKeyDescriptors(json, idp.getKeyDescriptor());
    }

    private static void appendSp(StringBuilder json, EntityDescriptorType entity) {
        SPSSODescriptorType sp = CoreConfigUtil.getSPDescriptor(entity);
        if (sp == null) {
            return;
        }
        json.append(',');
        append(json, "authnRequestsSigned", sp.isAuthnRequestsSigned());
        json.append(',');
        append(json, "wantAssertionsSigned", sp.isWantAssertionsSigned());
        json.append(',');
        appendIndexedEndpoints(json, "assertionConsumerServices", sp.getAssertionConsumerService());
        json.append(',');
        appendEndpoints(json, "singleLogoutServices", sp.getSingleLogoutService());
        json.append(',');
        appendKeyDescriptors(json, sp.getKeyDescriptor());
    }

    private static void appendEndpoints(StringBuilder json, String name, List<EndpointType> endpoints) {
        append(json, name, '[');
        if (endpoints != null) {
            for (int i = 0; i < endpoints.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                endpointObject(json, endpoints.get(i));
            }
        }
        json.append(']');
    }

    private static void appendIndexedEndpoints(StringBuilder json, String name, List<IndexedEndpointType> endpoints) {
        append(json, name, '[');
        if (endpoints != null) {
            for (int i = 0; i < endpoints.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                indexedEndpointObject(json, endpoints.get(i));
            }
        }
        json.append(']');
    }

    private static void endpointObject(StringBuilder json, EndpointType endpoint) {
        json.append('{');
        field(json, "binding", uri(endpoint.getBinding()));
        json.append(',');
        field(json, "location", uri(endpoint.getLocation()));
        if (endpoint.getResponseLocation() != null) {
            json.append(',');
            field(json, "responseLocation", uri(endpoint.getResponseLocation()));
        }
        json.append('}');
    }

    private static void indexedEndpointObject(StringBuilder json, IndexedEndpointType endpoint) {
        json.append('{');
        field(json, "binding", uri(endpoint.getBinding()));
        json.append(',');
        field(json, "location", uri(endpoint.getLocation()));
        if (endpoint.getResponseLocation() != null) {
            json.append(',');
            field(json, "responseLocation", uri(endpoint.getResponseLocation()));
        }
        if (endpoint.isIsDefault() != null) {
            json.append(',');
            append(json, "isDefault", endpoint.isIsDefault());
        }
        json.append('}');
    }

    private static void appendKeyDescriptors(StringBuilder json, List<KeyDescriptorType> keys) {
        append(json, "keyDescriptors", '[');
        if (keys != null) {
            for (int i = 0; i < keys.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                KeyDescriptorType key = keys.get(i);
                KeyTypes use = key.getUse();
                json.append('{');
                append(json, "signing", use == null || use == KeyTypes.SIGNING);
                json.append(',');
                append(json, "encryption", use == null || use == KeyTypes.ENCRYPTION);
                json.append('}');
            }
        }
        json.append(']');
    }

    private static void field(StringBuilder json, String name, String value) {
        append(json, name, quote(value));
    }

    private static void append(StringBuilder json, String name, boolean value) {
        json.append('"').append(escape(name)).append("\":").append(value);
    }

    private static void append(StringBuilder json, String name, char value) {
        json.append('"').append(escape(name)).append("\":").append(value);
    }

    private static void append(StringBuilder json, String name, String value) {
        json.append('"').append(escape(name)).append("\":").append(value);
    }

    private static String quote(String value) {
        return value == null ? "null" : "\"" + escape(value) + "\"";
    }

    private static String uri(URI uri) {
        return uri == null ? null : uri.toASCIIString();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
