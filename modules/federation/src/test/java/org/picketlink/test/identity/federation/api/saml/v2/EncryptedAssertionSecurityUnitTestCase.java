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
package org.picketlink.test.identity.federation.api.saml.v2;

import junit.framework.TestCase;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.util.EncryptedAssertionSecurityUtil;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerConfig;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest.GENERATE_REQUEST_TYPE;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;
import org.picketlink.identity.federation.core.util.XMLEncryptionUtil;
import org.picketlink.identity.federation.core.wstrust.WSTrustUtil;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.core.IdentityServer;
import org.picketlink.identity.federation.web.handlers.saml2.SAML2AuthenticationHandler;
import org.picketlink.identity.federation.web.handlers.saml2.SAML2SignatureGenerationHandler;
import org.picketlink.identity.federation.web.handlers.saml2.SAML2SignatureValidationHandler;
import org.picketlink.identity.federation.web.roles.DefaultRoleValidator;
import org.picketlink.test.identity.federation.web.mock.MockHttpServletRequest;
import org.picketlink.test.identity.federation.web.mock.MockHttpServletResponse;
import org.picketlink.test.identity.federation.web.mock.MockHttpSession;
import org.picketlink.test.identity.federation.web.mock.MockServletContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.namespace.QName;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tests encrypted assertion injection mitigation (CVE-2026-2092-class).
 */
public class EncryptedAssertionSecurityUnitTestCase extends TestCase {

    public void testSecurityCheckEnabledByDefault() {
        assertTrue(EncryptedAssertionSecurityUtil.ENCRYPTED_ASSERTION_SECURITY_CHECK_ENABLED);
    }

    public void testRejectsUnsignedEncryptedAssertionWhenResponseUnsigned() throws Exception {
        KeyPair keyPair = getKeyPair();
        Document signedAssertionOnlyResponse = createSignedAssertionOnlyResponse(keyPair);
        injectUnsignedEncryptedAssertionFirst(signedAssertionOnlyResponse, keyPair.getPublic());

        SAMLParser parser = new SAMLParser();
        ResponseType responseType = (ResponseType) parser.parse(DocumentUtil.getNodeAsStream(signedAssertionOnlyResponse));

        SAML2HandlerChainConfig chainConfig = createSpChainConfig(keyPair);
        SAML2HandlerConfig handlerConfig = new DefaultSAML2HandlerConfig();

        MockHttpSession session = new MockHttpSession();
        MockServletContext servletContext = new MockServletContext();
        session.setServletContext(servletContext);
        MockHttpServletRequest servletRequest = new MockHttpServletRequest(session, "POST");
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        HTTPContext httpContext = new HTTPContext(servletRequest, servletResponse, servletContext);

        SAMLDocumentHolder samlDocumentHolder = new SAMLDocumentHolder(signedAssertionOnlyResponse);
        samlDocumentHolder.setSamlObject(responseType);

        DefaultSAML2HandlerRequest request = new DefaultSAML2HandlerRequest(httpContext,
                responseType.getAssertions().get(1).getAssertion().getIssuer(), samlDocumentHolder,
                SAML2Handler.HANDLER_TYPE.SP);
        request.addOption(GeneralConstants.SENDER_PUBLIC_KEY, keyPair.getPublic());
        request.addOption(GeneralConstants.DECRYPTING_KEY, keyPair.getPrivate());

        SAML2HandlerResponse handlerResponse = new DefaultSAML2HandlerResponse();

        SAML2SignatureValidationHandler validationHandler = new SAML2SignatureValidationHandler();
        validationHandler.initChainConfig(chainConfig);
        validationHandler.initHandlerConfig(handlerConfig);
        validationHandler.handleStatusResponseType(request, handlerResponse);

        SAML2AuthenticationHandler authHandler = new SAML2AuthenticationHandler();
        authHandler.initChainConfig(chainConfig);
        authHandler.initHandlerConfig(handlerConfig);

        try {
            authHandler.handleStatusResponseType(request, handlerResponse);
            fail("Expected ProcessingException for unsigned encrypted assertion injection");
        } catch (ProcessingException e) {
            assertTrue("Response root should not be signed", !AssertionUtil.isSignedElement(
                    signedAssertionOnlyResponse.getDocumentElement()));
        }
    }

    private Document createSignedAssertionOnlyResponse(KeyPair keyPair) throws Exception {
        PicketLinkCoreSTS.instance().installDefaultConfiguration();

        SAML2HandlerChainConfig chainConfig = new DefaultSAML2HandlerChainConfig();
        Map<String, Object> chainOptions = new HashMap<String, Object>();
        SPType spType = new SPType();
        spType.setServiceURL("http://sp");
        chainOptions.put(GeneralConstants.CONFIGURATION, spType);
        chainOptions.put(GeneralConstants.KEYPAIR, keyPair);
        chainOptions.put(GeneralConstants.ROLE_VALIDATOR_IGNORE, "true");
        chainConfig.set(chainOptions);

        SAML2HandlerConfig handlerConfig = new DefaultSAML2HandlerConfig();
        handlerConfig.addParameter(SAML2SignatureGenerationHandler.SIGN_ASSERTION_ONLY, "true");

        SAML2Request saml2Request = new SAML2Request();
        String id = IDGenerator.create("ID_");
        AuthnRequestType authnRequest = saml2Request.createAuthnRequestType(id, "http://sp", "http://idp", "http://sp");
        Document authDoc = saml2Request.convert(authnRequest);

        MockHttpSession session = new MockHttpSession();
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest servletRequest = new MockHttpServletRequest(session, "POST");
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        HTTPContext httpContext = new HTTPContext(servletRequest, servletResponse, servletContext);

        SAMLDocumentHolder docHolder = new SAMLDocumentHolder(authnRequest, authDoc);
        IssuerInfoHolder issuerInfo = new IssuerInfoHolder("http://localhost:8080/idp/");
        SAML2HandlerRequest request = new DefaultSAML2HandlerRequest(httpContext, issuerInfo.getIssuer(), docHolder,
                SAML2Handler.HANDLER_TYPE.IDP);
        request.setTypeOfRequestToBeGenerated(GENERATE_REQUEST_TYPE.AUTH);

        SAML2HandlerResponse response = new DefaultSAML2HandlerResponse();
        response.setPostBindingForResponse(true);

        Map<String, Object> chainOptionsIdp = new HashMap<String, Object>();
        IDPType idpType = new IDPType();
        idpType.setSupportsSignature(true);
        idpType.setIdentityURL("http://idp");
        chainOptionsIdp.put(GeneralConstants.CONFIGURATION, idpType);
        chainOptionsIdp.put(GeneralConstants.KEYPAIR, keyPair);
        SAML2HandlerChainConfig chainConfigIdp = new DefaultSAML2HandlerChainConfig(chainOptionsIdp);

        SAML2AuthenticationHandler idpAuthenticationHandler = new SAML2AuthenticationHandler();
        idpAuthenticationHandler.initChainConfig(chainConfigIdp);
        idpAuthenticationHandler.initHandlerConfig(handlerConfig);

        MockHttpSession idpSession = new MockHttpSession();
        MockServletContext idpServletContext = new MockServletContext();
        idpSession.setServletContext(idpServletContext);
        IdentityServer server = new IdentityServer();
        idpServletContext.setAttribute("IDENTITY_SERVER", server);
        HTTPContext idpHttpContext = new HTTPContext(servletRequest, servletResponse, idpServletContext);
        SAML2HandlerRequest idpHandlerRequest = new DefaultSAML2HandlerRequest(idpHttpContext, issuerInfo.getIssuer(), docHolder,
                SAML2Handler.HANDLER_TYPE.IDP);
        idpHandlerRequest.addOption(GeneralConstants.ASSERTIONS_VALIDITY, 60L * 60L * 1000L);
        SAML2HandlerResponse idpHandlerResponse = new DefaultSAML2HandlerResponse();

        idpAuthenticationHandler.handleRequestType(idpHandlerRequest, idpHandlerResponse);

        chainConfigIdp.addParameter(GeneralConstants.ROLE_VALIDATOR, new DefaultRoleValidator() {
            @Override
            public boolean userInRole(Principal userPrincipal, List<String> roles) {
                return true;
            }
        });

        SAML2SignatureGenerationHandler idpSignatureGenerationHandler = new SAML2SignatureGenerationHandler();
        idpSignatureGenerationHandler.initChainConfig(chainConfigIdp);
        idpSignatureGenerationHandler.initHandlerConfig(handlerConfig);
        idpSignatureGenerationHandler.handleStatusResponseType(idpHandlerRequest, idpHandlerResponse);

        return idpHandlerResponse.getResultingDocument();
    }

    private void injectUnsignedEncryptedAssertionFirst(Document document, PublicKey publicKey) throws Exception {
        removeDocumentSignature(document);

        Element assertion = (Element) document.getElementsByTagNameNS(
                JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.ASSERTION.get()).item(0);

        Element evilAssertion = (Element) assertion.cloneNode(true);
        evilAssertion.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:" + assertion.getPrefix(),
                JBossSAMLURIConstants.ASSERTION_NSURI.get());

        NodeList signatures = evilAssertion.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (signatures.getLength() > 0) {
            evilAssertion.removeChild(signatures.item(0));
        }

        NodeList nameIds = evilAssertion.getElementsByTagNameNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(), "NameID");
        if (nameIds.getLength() > 0) {
            nameIds.item(0).setTextContent("attacker");
        }

        document.getDocumentElement().insertBefore(evilAssertion, assertion);

        byte[] secret = WSTrustUtil.createRandomSecret(128 / 8);
        SecretKeySpec secretKey = new SecretKeySpec(secret, "AES");
        String assertionNS = JBossSAMLURIConstants.ASSERTION_NSURI.get();
        QName encryptedAssertionQName = new QName(assertionNS, JBossSAMLConstants.ENCRYPTED_ASSERTION.get(), assertion.getPrefix());

        XMLEncryptionUtil.encryptElement(
                new QName(assertionNS, JBossSAMLConstants.ASSERTION.get(), assertion.getPrefix()),
                document,
                publicKey,
                secretKey,
                128,
                encryptedAssertionQName,
                true);
    }

    private void removeDocumentSignature(Document document) {
        Element response = document.getDocumentElement();
        NodeList children = response.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            if (children.item(i) instanceof Element) {
                Element child = (Element) children.item(i);
                if (XMLSignature.XMLNS.equals(child.getNamespaceURI()) && "Signature".equals(child.getLocalName())) {
                    response.removeChild(child);
                }
            }
        }
    }

    private SAML2HandlerChainConfig createSpChainConfig(KeyPair keyPair) {
        Map<String, Object> chainOptions = new HashMap<String, Object>();
        SPType spType = new SPType();
        spType.setServiceURL("http://sp");
        chainOptions.put(GeneralConstants.CONFIGURATION, spType);
        chainOptions.put(GeneralConstants.KEYPAIR, keyPair);
        chainOptions.put(GeneralConstants.ROLE_VALIDATOR_IGNORE, "true");
        SAML2HandlerChainConfig chainConfig = new DefaultSAML2HandlerChainConfig();
        chainConfig.set(chainOptions);
        return chainConfig;
    }

    private KeyPair getKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        return kpg.genKeyPair();
    }
}
