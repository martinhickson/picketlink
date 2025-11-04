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
package org.picketlink.identity.federation.web.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.config.PicketLinkConfigParser;
import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.SPType;
import org.picketlink.config.federation.handler.Handlers;
import org.picketlink.config.federation.parsers.SAMLConfigParser;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditHelper;
import org.picketlink.identity.federation.web.config.AbstractSAMLConfigurationProvider;

import jakarta.servlet.ServletContext;

import static org.picketlink.common.constants.GeneralConstants.AUDIT_HELPER;
import static org.picketlink.common.constants.GeneralConstants.CONFIG_FILE_LOCATION;
import static org.picketlink.common.constants.GeneralConstants.CONFIG_PROVIDER;
import static org.picketlink.common.util.StringUtil.isNullOrEmpty;

/**
 * Deals with Configuration
 *
 * @author Anil.Saldhana@redhat.com
 * @since Aug 21, 2009
 */
public class ConfigurationUtil {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    public static PicketLinkType getConfiguration(InputStream is) throws ParsingException {
        if (is == null)
            throw logger.nullArgumentError("inputstream");
        PicketLinkConfigParser parser = new PicketLinkConfigParser();
        PicketLinkType picketLinkType = (PicketLinkType) parser.parse(is);
        return picketLinkType;
    }

    /**
     * Get the IDP Configuration from the passed configuration
     *
     * @param is
     *
     * @return
     *
     * @throws ParsingException
     */
    public static IDPType getIDPConfiguration(InputStream is) throws ParsingException {
        if (is == null)
            throw logger.nullArgumentError("inputstream");

        SAMLConfigParser parser = new SAMLConfigParser();
        return (IDPType) parser.parse(is);
    }

    /**
     * Get the SP Configuration from the passed inputstream
     *
     * @param is
     *
     * @return
     *
     * @throws ParsingException
     */
    public static SPType getSPConfiguration(InputStream is) throws ParsingException {
        if (is == null)
            throw logger.nullArgumentError("inputstream");
        return (SPType) (new SAMLConfigParser()).parse(is);
    }

    /**
     * Get the Handlers from the configuration
     *
     * @param is
     *
     * @return
     *
     * @throws ParsingException
     */
    public static Handlers getHandlers(InputStream is) throws ParsingException {
        if (is == null)
            throw logger.nullArgumentError("inputstream");
        return (Handlers) (new SAMLConfigParser()).parse(is);
    }

    public static PicketLinkType getConfiguration(ServletContext servletContext) throws ProcessingException, ConfigurationException {
        SAMLConfigurationProvider configurationProvider = getConfigurationProvider(servletContext);

        if (configurationProvider != null) {
            logger.debug("Loading PicketLink configuration configuration provider [" + configurationProvider + "].");
            return configurationProvider.getPicketLinkConfiguration();
        }

        logger.debug("Loading PicketLink configuration from [" + CONFIG_FILE_LOCATION + "].");

        InputStream is = getConfigurationInputStream(servletContext);

        if (is != null) {
            try {
                return getConfiguration(is);
            } catch (ParsingException e) {
                throw logger.configurationError(e);
            } finally {
                try {
                    is.close();
                } catch (IOException ignore) {
                }
            }
        }

        return null;
    }

    public static SAMLConfigurationProvider getConfigurationProvider(ServletContext servletContext) {
        String configProviderType = servletContext.getInitParameter(CONFIG_PROVIDER);

        if (configProviderType != null) {
            try {
                SAMLConfigurationProvider configurationProvider = (SAMLConfigurationProvider) SecurityActions
                        .loadClass(Thread.currentThread().getContextClassLoader(), configProviderType).newInstance();

                if (AbstractSAMLConfigurationProvider.class.isInstance(configurationProvider)) {
                    InputStream inputStream = getConfigurationInputStream(servletContext);

                    if (inputStream != null) {
                        ((AbstractSAMLConfigurationProvider) configurationProvider).setConsolidatedConfigFile(inputStream);
                    }
                }

                return configurationProvider;
            } catch (Exception e) {
                throw new RuntimeException("Could not create config provider [" + configProviderType + "].", e);
            }
        }

        return null;
    }

    public static PicketLinkAuditHelper getAuditHelper(ServletContext servletContext) {
        String auditHelperType = servletContext.getInitParameter(AUDIT_HELPER);

        if (auditHelperType == null) {
            auditHelperType = PicketLinkAuditHelper.class.getName();
        }

        logger.debug("Creating audit helper [" + auditHelperType + "].");

        try {
            return (PicketLinkAuditHelper) SecurityActions
                    .loadClass(Thread.currentThread().getContextClassLoader(), auditHelperType)
                        .getConstructor(ServletContext.class)
                            .newInstance(servletContext);
        } catch (Exception e) {
            throw new RuntimeException("Could not create audit helper [" + auditHelperType + "].", e);
        }
    }

    public static InputStream getConfigurationInputStream(ServletContext servletContext) {
        String configFile = servletContext.getInitParameter(GeneralConstants.CONFIG_FILE);

        if (isNullOrEmpty(configFile)) {
            return servletContext.getResourceAsStream(CONFIG_FILE_LOCATION);
        } else {
            try {
                return new FileInputStream(configFile);
            } catch (FileNotFoundException e) {
                throw logger.samlIDPConfigurationError(e);
            }
        }
    }
}