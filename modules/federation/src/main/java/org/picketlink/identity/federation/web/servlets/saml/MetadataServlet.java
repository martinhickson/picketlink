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
package org.picketlink.identity.federation.web.servlets.saml;

import org.jboss.logging.Logger;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.StaxUtil;
import org.picketlink.config.federation.AuthPropertyType;
import org.picketlink.config.federation.KeyProviderType;
import org.picketlink.config.federation.KeyValueType;
import org.picketlink.config.federation.MetadataProviderType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.identity.federation.api.util.SamlCryptoSecurityUtil;
import org.picketlink.identity.federation.api.saml.v2.metadata.KeyDescriptorMetaDataBuilder;
import org.picketlink.identity.federation.api.util.KeyUtil;
import org.picketlink.identity.federation.core.interfaces.IMetadataProvider;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.saml.md.providers.IDPMetadataProvider;
import org.picketlink.identity.federation.core.saml.v2.writers.SAMLMetadataWriter;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.core.util.XMLEncryptionUtil;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.picketlink.common.util.StringUtil.isNotNull;

/**
 * Metadata servlet for the IDP/SP
 *
 * @author Anil.Saldhana@redhat.com
 * @since Apr 22, 2009
 */
public class MetadataServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static Logger log = Logger.getLogger(MetadataServlet.class);

    private final boolean trace = log.isTraceEnabled();

    private String configFileLocation = GeneralConstants.CONFIG_FILE_LOCATION;

    private transient MetadataProviderType metadataProviderType = null;

    private transient IMetadataProvider<?> metadataProvider = null;

    private transient EntityDescriptorType metadata;

    private transient ProviderType providerType;

    private String signingAlias = null;

    private String encryptingAlias = null;

    private TrustKeyManager keyManager;

    @SuppressWarnings("rawtypes")
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            ServletContext context = config.getServletContext();
            String configL = config.getInitParameter("configFile");
            if (isNotNull(configL))
                configFileLocation = configL;
            if (trace)
                log.trace("Config File Location=" + configFileLocation);
            InputStream is = context.getResourceAsStream(configFileLocation);
            if (is == null)
                throw new RuntimeException(ErrorCodes.RESOURCE_NOT_FOUND + configFileLocation + " missing");

            signingAlias = config.getInitParameter("signingAlias");
            encryptingAlias = config.getInitParameter("encryptingAlias");

            ProviderType providerType = ConfigurationUtil.getIDPConfiguration(is);
            this.providerType = providerType;
            metadataProviderType = providerType.getMetaDataProvider();
            String fqn = metadataProviderType.getClassName();
            Class<?> clazz = SecurityActions.loadClass(getClass(), fqn);
            metadataProvider = (IMetadataProvider) clazz.newInstance();
            List<KeyValueType> keyValues = metadataProviderType.getOption();
            Map<String, String> options = new HashMap<String, String>();
            if (keyValues != null) {
                for (KeyValueType kvt : keyValues)
                    options.put(kvt.getKey(), kvt.getValue());
            }

            if (isIdpMetadataProvider(metadataProvider)) {
                PicketLinkType picketLinkType = new PicketLinkType();
                picketLinkType.setIdpOrSP(providerType);
                ((IDPMetadataProvider) metadataProvider).setPicketLinkConf(picketLinkType);
            }

            metadataProvider.init(options);
            if (metadataProvider.isMultiple())
                throw new RuntimeException(ErrorCodes.NOT_IMPLEMENTED_YET + "Multiple Entities not currently supported");

            String fileInjectionStr = metadataProvider.requireFileInjection();
            if (isNotNull(fileInjectionStr)) {
                metadataProvider.injectFileStream(context.getResourceAsStream(fileInjectionStr));
            }

            metadata = (EntityDescriptorType) metadataProvider.getMetaData();

            KeyProviderType keyProvider = providerType.getKeyProvider();
            signingAlias = keyProvider.getSigningAlias();
            String keyManagerClassName = keyProvider.getClassName();
            if (keyManagerClassName == null)
                throw new RuntimeException(ErrorCodes.NULL_VALUE + "KeyManager class name");

            clazz = SecurityActions.loadClass(getClass(), keyManagerClassName);
            this.keyManager = (TrustKeyManager) clazz.newInstance();

            List<AuthPropertyType> authProperties = CoreConfigUtil.getKeyProviderProperties(keyProvider);
            keyManager.setAuthProperties(authProperties);

            Certificate cert = keyManager.getCertificate(signingAlias);
            Element keyInfo = KeyUtil.getKeyInfo(cert);

            KeyDescriptorType keyDescriptor = KeyDescriptorMetaDataBuilder.createKeyDescriptor(keyInfo, null, 0, true, false);

            updateKeyDescriptor(metadata, keyDescriptor);

            if (encryptingAlias != null) {
                cert = keyManager.getCertificate(encryptingAlias);
                keyInfo = KeyUtil.getKeyInfo(cert);
                String certAlgo = cert.getPublicKey().getAlgorithm();
                keyDescriptor = KeyDescriptorMetaDataBuilder.createKeyDescriptor(keyInfo,
                        XMLEncryptionUtil.getEncryptionURL(certAlgo), XMLEncryptionUtil.getEncryptionKeySize(certAlgo), false,
                        true);
                updateKeyDescriptor(metadata, keyDescriptor);
            } else if (isIdpMetadataProvider(metadataProvider)) {
                encryptingAlias = signingAlias;
                cert = keyManager.getCertificate(encryptingAlias);
                keyInfo = KeyUtil.getKeyInfo(cert);
                keyDescriptor = KeyDescriptorMetaDataBuilder.createKeyDescriptor(keyInfo, null, 0, false, true);
                updateKeyDescriptor(metadata, keyDescriptor);
            }

            if (isIdpMetadataProvider(metadataProvider)) {
                signAndAddAttribs(metadata);
            }
        } catch (Exception e) {
            log.error("Exception in starting servlet:", e);
            throw new ServletException(ErrorCodes.PROCESSING_EXCEPTION + "Unable to start servlet");
        }

    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType(JBossSAMLConstants.METADATA_MIME.get());
        OutputStream os = resp.getOutputStream();

        try {
            XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(os);
            SAMLMetadataWriter writer = new SAMLMetadataWriter(streamWriter);
            writer.writeEntityDescriptor(metadata);
        } catch (ProcessingException e) {
            throw new ServletException(e);
        }
    }

    private static boolean isIdpMetadataProvider(IMetadataProvider<?> provider) {
        return provider instanceof IDPMetadataProvider
                || IDPMetadataProvider.class.getName().equals(provider.getClass().getName());
    }

    private void signAndAddAttribs(EntityDescriptorType entityDescriptor) throws ServletException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(baos);
            SAMLMetadataWriter writer = new SAMLMetadataWriter(streamWriter);
            writer.writeEntityDescriptor(entityDescriptor);
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            String feature = "";
            try {
                feature = DocumentUtil.feature_disallow_doctype_decl;
                documentBuilderFactory.setFeature(feature, true);
                feature = DocumentUtil.feature_external_general_entities;
                documentBuilderFactory.setFeature(feature, false);
                feature = DocumentUtil.feature_external_parameter_entities;
                documentBuilderFactory.setFeature(feature, false);
            } catch (ParserConfigurationException e) {
                throw new ServletException(e);
            }
            Document doc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            KeyPair keyPair = new KeyPair(null, keyManager.getSigningKey());
            Element root = doc.getDocumentElement();
            XMLSignatureUtil.sign(root, root.getFirstChild(), keyPair,
                    SamlCryptoSecurityUtil.getDigestMethodForSigning(isLegacySigningEnabled()),
                    SamlCryptoSecurityUtil.getSignatureMethodForSigning(isLegacySigningEnabled()), "",
                    (X509Certificate) keyManager.getCertificate(signingAlias));
            entityDescriptor.setSignature((Element) root.getFirstChild());
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

    private void updateKeyDescriptor(EntityDescriptorType entityD, KeyDescriptorType keyD) {
        List<EDTDescriptorChoiceType> objs = entityD.getChoiceType().get(0).getDescriptors();
        if (objs != null) {
            for (EDTDescriptorChoiceType choiceTypeDesc : objs) {
                AttributeAuthorityDescriptorType attribDescriptor = choiceTypeDesc.getAttribDescriptor();
                if (attribDescriptor != null)
                    attribDescriptor.addKeyDescriptor(keyD);
                AuthnAuthorityDescriptorType authnDescriptor = choiceTypeDesc.getAuthnDescriptor();
                if (authnDescriptor != null)
                    authnDescriptor.addKeyDescriptor(keyD);
                IDPSSODescriptorType idpDescriptor = choiceTypeDesc.getIdpDescriptor();
                if (idpDescriptor != null)
                    idpDescriptor.addKeyDescriptor(keyD);
                PDPDescriptorType pdpDescriptor = choiceTypeDesc.getPdpDescriptor();
                if (pdpDescriptor != null)
                    pdpDescriptor.addKeyDescriptor(keyD);
                RoleDescriptorType roleDescriptor = choiceTypeDesc.getRoleDescriptor();
                if (roleDescriptor != null)
                    roleDescriptor.addKeyDescriptor(keyD);
                SPSSODescriptorType spDescriptor = choiceTypeDesc.getSpDescriptor();
                if (spDescriptor != null)
                    spDescriptor.addKeyDescriptor(keyD);
            }
        }
    }

    private boolean isLegacySigningEnabled() {
        return providerType != null && providerType.isEnableLegacySigning();
    }
}
