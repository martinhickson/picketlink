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
package org.picketlink.identity.federation.core.saml.md.providers;


import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.config.federation.SPType;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.config.federation.handler.Handler;
import org.picketlink.config.federation.handler.Handlers;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;

import java.io.InputStream;

/**
 * Author: coluccelli@redhat.com
 */
public class MetadataProviderUtils {

    /**
     * Global logout destination on the IDP (SP {@code LogoutUrl} config attribute).
     */
    public static String getGlobalLogoutUrl(ProviderType providerType) {
        if (providerType instanceof SPType) {
            return ((SPType) providerType).getLogoutUrl();
        }
        return null;
    }

    /**
     * Local post-logout page on the SP ({@code LogOutPage} config attribute).
     */
    public static String getLogOutPage(ProviderType providerType) {
        if (providerType instanceof SPType) {
            return ((SPType) providerType).getLogOutPage();
        }
        return null;
    }

    /**
     * Where this SP receives Single Logout requests (published metadata {@code Location}).
     */
    public static String getSingleLogoutServiceLocation(ProviderType providerType) {
        if (providerType instanceof SPType) {
            return ((SPType) providerType).getServiceURL();
        }
        if (providerType instanceof IDPType) {
            return providerType.getIdentityURL();
        }
        return null;
    }

    /**
     * Where logout responses are sent ({@code ResponseLocation} on {@code SingleLogoutService}).
     */
    public static String getSingleLogoutServiceResponseLocation(ProviderType providerType) {
        if (providerType instanceof SPType) {
            SPType spType = (SPType) providerType;
            if (isNotBlank(spType.getLogoutResponseLocation())) {
                return spType.getLogoutResponseLocation();
            }
            return resolveRelativeUrl(spType.getServiceURL(), spType.getLogOutPage());
        }
        if (providerType instanceof IDPType) {
            return ((IDPType) providerType).getHostedURI();
        }
        return null;
    }

    public static String getServiceURL(ProviderType providerType) {
        if (providerType instanceof SPType) {
            return ((SPType) providerType).getServiceURL();
        }
        return null;
    }

    public static String getIdentityURL(ProviderType providerType) {
        return providerType != null ? providerType.getIdentityURL() : null;
    }

    public static String getBindingURI(ProviderType providerType) {
        if (providerType instanceof SPType) {
            return bindingUriFromType(((SPType) providerType).getBindingType());
        }
        if (providerType instanceof IDPType) {
            IDPType idpType = (IDPType) providerType;
            return idpType.isStrictPostBinding()
                    ? JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get()
                    : JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();
        }
        return null;
    }

    public static String bindingUriFromType(String bindingType) {
        if ("POST".equalsIgnoreCase(bindingType)) {
            return JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
        }
        if ("REDIRECT".equalsIgnoreCase(bindingType)) {
            return JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();
        }
        return null;
    }

    public static String resolveRelativeUrl(String baseUrl, String path) {
        if (!isNotBlank(path)) {
            return null;
        }
        if (path.contains("://")) {
            return path;
        }
        if (!isNotBlank(baseUrl)) {
            return path.startsWith("/") ? path : "/" + path;
        }
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return base + path;
    }

    public static PicketLinkType getPicketLinkConf(InputStream is) {
        try {
            return ConfigurationUtil.getConfiguration(is);
        } catch (ParsingException e) {
            throw new RuntimeException(e);
        }
    }

    public static ProviderType getProviderType(PicketLinkType picketLinkConfiguration) {
        ProviderType providerType = null;
        if (picketLinkConfiguration != null) {
            providerType = picketLinkConfiguration.getIdpOrSP();
        }
        return providerType;
    }

    public static Handler getHandler(PicketLinkType picketLinkType, String handlerName) throws ParsingException {
        Handlers handlers = picketLinkType.getHandlers();
        if (handlers == null) {
            return null;
        }
        for (Handler h : handlers.getHandler()) {
            if (h.getClazz().equals(handlerName)) {
                return h;
            }
        }
        return null;
    }

    private static boolean isNotBlank(String value) {
        return value != null && !value.isBlank();
    }

}
