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

import org.picketlink.common.ErrorCodes;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.config.federation.AuthPropertyType;
import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.KeyProviderType;
import org.picketlink.config.federation.KeyValueType;
import org.picketlink.config.federation.MetadataProviderType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.config.federation.SPType;
import org.picketlink.config.federation.parsers.SAMLConfigParser;
import org.picketlink.identity.federation.api.saml.v2.metadata.KeyDescriptorMetaDataBuilder;
import org.picketlink.identity.federation.api.util.KeyUtil;
import org.picketlink.identity.federation.core.interfaces.IMetadataProvider;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.saml.md.providers.IDPMetadataProvider;
import org.picketlink.identity.federation.core.saml.md.providers.SPMetadataProvider;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.saml.v2.metadata.AttributeAuthorityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.AuthnAuthorityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType.EDTDescriptorChoiceType;
import org.picketlink.identity.federation.saml.v2.metadata.IDPSSODescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.PDPDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.RoleDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.SPSSODescriptorType;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;

import jakarta.servlet.ServletContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.picketlink.common.util.StringUtil.isNotNull;

/**
 * Loads published SAML entity metadata from the configured {@link IMetadataProvider}.
 */
public final class MetadataPublishingLoader {

    private MetadataPublishingLoader() {
    }

    public static LoadedMetadata load(ServletContext servletContext, String configFileLocation) throws Exception {
        ProviderType providerType = resolveProviderType(servletContext, configFileLocation);
        if (providerType == null) {
            throw new RuntimeException(ErrorCodes.RESOURCE_NOT_FOUND + configFileLocation + " missing or invalid");
        }
        MetadataProviderType metadataProviderType = providerType.getMetaDataProvider();
        if (metadataProviderType == null) {
            throw new RuntimeException("MetaDataProvider is not configured");
        }

        String fqn = metadataProviderType.getClassName();
        Class<?> clazz = SecurityActions.loadClass(MetadataPublishingLoader.class, fqn);
        @SuppressWarnings("rawtypes")
        IMetadataProvider metadataProvider = (IMetadataProvider) clazz.newInstance();

        Map<String, String> options = new HashMap<String, String>();
        List<KeyValueType> keyValues = metadataProviderType.getOption();
        if (keyValues != null) {
            for (KeyValueType kvt : keyValues) {
                options.put(kvt.getKey(), kvt.getValue());
            }
        }

        if (isSpMetadataProvider(metadataProvider)) {
            PicketLinkType picketLinkType = new PicketLinkType();
            picketLinkType.setIdpOrSP(providerType);
            ((SPMetadataProvider) metadataProvider).setPicketLinkConf(picketLinkType);
        } else if (isIdpMetadataProvider(metadataProvider)) {
            PicketLinkType picketLinkType = new PicketLinkType();
            picketLinkType.setIdpOrSP(providerType);
            ((IDPMetadataProvider) metadataProvider).setPicketLinkConf(picketLinkType);
        }

        metadataProvider.init(options);
        if (metadataProvider.isMultiple()) {
            throw new RuntimeException(ErrorCodes.NOT_IMPLEMENTED_YET + "Multiple Entities not currently supported");
        }

        String fileInjectionStr = metadataProvider.requireFileInjection();
        if (isNotNull(fileInjectionStr)) {
            metadataProvider.injectFileStream(servletContext.getResourceAsStream(fileInjectionStr));
        }

        EntityDescriptorType metadata = (EntityDescriptorType) metadataProvider.getMetaData();
        injectKeyDescriptors(metadata, providerType);

        String role = providerType instanceof IDPType ? "IDP" : providerType instanceof SPType ? "SP" : "UNKNOWN";
        return new LoadedMetadata(metadata, role, providerType);
    }

    public static ProviderType resolveProviderType(ServletContext servletContext, String configFileLocation)
            throws ParsingException {
        InputStream configStream = servletContext.getResourceAsStream(configFileLocation);
        if (configStream == null) {
            return null;
        }
        return resolveProviderType(configStream);
    }

    private static ProviderType resolveProviderType(InputStream configStream) throws ParsingException {
        byte[] data = readAll(configStream);
        try {
            PicketLinkType picketLinkType = ConfigurationUtil.getConfiguration(new ByteArrayInputStream(data));
            ProviderType providerType = picketLinkType.getIdpOrSP();
            if (providerType != null) {
                return providerType;
            }
        } catch (Exception ignored) {
            // not a consolidated PicketLink wrapper document — try direct IDP/SP config
        }
        SAMLConfigParser parser = new SAMLConfigParser();
        return (ProviderType) parser.parse(new ByteArrayInputStream(data));
    }

    private static byte[] readAll(InputStream inputStream) throws ParsingException {
        try {
            return inputStream.readAllBytes();
        } catch (IOException e) {
            throw new ParsingException(e);
        }
    }

    private static void injectKeyDescriptors(EntityDescriptorType metadata, ProviderType providerType) throws Exception {
        KeyProviderType keyProvider = providerType.getKeyProvider();
        if (keyProvider == null) {
            return;
        }

        String signingAlias = keyProvider.getSigningAlias();
        String keyManagerClassName = keyProvider.getClassName();
        if (keyManagerClassName == null) {
            throw new RuntimeException(ErrorCodes.NULL_VALUE + "KeyManager class name");
        }

        Class<?> clazz = SecurityActions.loadClass(MetadataPublishingLoader.class, keyManagerClassName);
        TrustKeyManager keyManager = (TrustKeyManager) clazz.newInstance();
        List<AuthPropertyType> authProperties = CoreConfigUtil.getKeyProviderProperties(keyProvider);
        keyManager.setAuthProperties(authProperties);

        Certificate cert = keyManager.getCertificate(signingAlias);
        org.w3c.dom.Element keyInfo = KeyUtil.getKeyInfo(cert);
        KeyDescriptorType keyDescriptor = KeyDescriptorMetaDataBuilder.createKeyDescriptor(keyInfo, null, 0, true, false);
        updateKeyDescriptor(metadata, keyDescriptor);

        if (providerType instanceof IDPType) {
            cert = keyManager.getCertificate(signingAlias);
            keyInfo = KeyUtil.getKeyInfo(cert);
            keyDescriptor = KeyDescriptorMetaDataBuilder.createKeyDescriptor(keyInfo, null, 0, false, true);
            updateKeyDescriptor(metadata, keyDescriptor);
        }
    }

    private static void updateKeyDescriptor(EntityDescriptorType entityD, KeyDescriptorType keyD) {
        List<EDTDescriptorChoiceType> objs = entityD.getChoiceType().get(0).getDescriptors();
        if (objs == null) {
            return;
        }
        for (EDTDescriptorChoiceType choiceTypeDesc : objs) {
            AttributeAuthorityDescriptorType attribDescriptor = choiceTypeDesc.getAttribDescriptor();
            if (attribDescriptor != null) {
                attribDescriptor.addKeyDescriptor(keyD);
            }
            AuthnAuthorityDescriptorType authnDescriptor = choiceTypeDesc.getAuthnDescriptor();
            if (authnDescriptor != null) {
                authnDescriptor.addKeyDescriptor(keyD);
            }
            IDPSSODescriptorType idpDescriptor = choiceTypeDesc.getIdpDescriptor();
            if (idpDescriptor != null) {
                idpDescriptor.addKeyDescriptor(keyD);
            }
            PDPDescriptorType pdpDescriptor = choiceTypeDesc.getPdpDescriptor();
            if (pdpDescriptor != null) {
                pdpDescriptor.addKeyDescriptor(keyD);
            }
            RoleDescriptorType roleDescriptor = choiceTypeDesc.getRoleDescriptor();
            if (roleDescriptor != null) {
                roleDescriptor.addKeyDescriptor(keyD);
            }
            SPSSODescriptorType spDescriptor = choiceTypeDesc.getSpDescriptor();
            if (spDescriptor != null) {
                spDescriptor.addKeyDescriptor(keyD);
            }
        }
    }

    private static boolean isIdpMetadataProvider(IMetadataProvider<?> provider) {
        return provider instanceof IDPMetadataProvider
                || IDPMetadataProvider.class.getName().equals(provider.getClass().getName());
    }

    private static boolean isSpMetadataProvider(IMetadataProvider<?> provider) {
        return provider instanceof SPMetadataProvider
                || SPMetadataProvider.class.getName().equals(provider.getClass().getName());
    }

    public static final class LoadedMetadata {
        private final EntityDescriptorType entityDescriptor;
        private final String role;
        private final ProviderType providerType;

        LoadedMetadata(EntityDescriptorType entityDescriptor, String role, ProviderType providerType) {
            this.entityDescriptor = entityDescriptor;
            this.role = role;
            this.providerType = providerType;
        }

        public EntityDescriptorType getEntityDescriptor() {
            return entityDescriptor;
        }

        public String getRole() {
            return role;
        }

        public ProviderType getProviderType() {
            return providerType;
        }
    }
}
