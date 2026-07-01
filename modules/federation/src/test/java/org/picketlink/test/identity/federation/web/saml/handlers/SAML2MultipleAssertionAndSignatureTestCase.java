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
package org.picketlink.test.identity.federation.web.saml.handlers;

import static org.picketlink.common.constants.GeneralConstants.PRINCIPAL_ID;
import static org.picketlink.common.constants.GeneralConstants.SAML_SIGNATURE_REQUEST_KEY;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.junit.Test;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.exceptions.fed.SignatureValidationException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
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
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
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

import javax.xml.crypto.dsig.XMLSignatureException;

/**
 * Unit test the {@code SAML2SignatureHandler}
 *
 * @author Anil.Saldhana@redhat.com
 * @since Oct 12, 2009
 */
public class SAML2MultipleAssertionAndSignatureTestCase extends TestCase {

    @Test
    public void testSignaturesPostBinding() throws Exception {
        doSignatureTest(true, new DefaultSAML2HandlerConfig(), false, false, false);
    }

    @Test
    public void testSignaturesPostBindingNegativeType1() throws Exception {
        String typeOfIntroducedProblem = "Type of problem(addBadAssertionWithoutSignature):";
        try {
            doSignatureTest(true, new DefaultSAML2HandlerConfig(), true, false, false);
        } catch (ProcessingException e) {
            Assert.assertTrue(typeOfIntroducedProblem + "signature validation should fail", isSignatureValidationFailure(e));
            return;
        }
        Assert.fail(typeOfIntroducedProblem+"ProcessingException expected");
    }

    @Test
    public void testSignaturesPostBindingNegativeType2() throws Exception {
        String typeOfIntroducedProblem = "Type of problem(addFakeGoodAssertionWithoutSignature):";
        try {
            doSignatureTest(true, new DefaultSAML2HandlerConfig(), false, true, false);
        } catch (ProcessingException e) {
            Assert.assertTrue(typeOfIntroducedProblem + "signature validation should fail", isSignatureValidationFailure(e));
            return;
        }
        Assert.fail(typeOfIntroducedProblem+"ProcessingException expected");
    }

    @Test
    public void testSignaturesPostBindingNegativeType3() throws Exception {
        String typeOfIntroducedProblem = "Type of problem(addBadAssertionWithSignature):";
        try {
            doSignatureTest(true, new DefaultSAML2HandlerConfig(), false, false, true);
        } catch (ProcessingException e) {
            Assert.assertTrue(typeOfIntroducedProblem + "signature validation should fail", isSignatureValidationFailure(e));
            return;
        }
        Assert.fail(typeOfIntroducedProblem+"ProcessingException expected");
    }


    @Test
    public void testSignaturesRedirectBinding() throws Exception {
        doSignatureTest(false, new DefaultSAML2HandlerConfig(), false, false, false);
    }

    @Test
    public void testSignaturesRedirectBindingNegativeType1() throws Exception {
        String typeOfIntroducedProblem = "Type of problem(addBadAssertionWithoutSignature):";
        try {
            doSignatureTest(false, new DefaultSAML2HandlerConfig(), false, false, true);
        } catch (ProcessingException e) {
            Assert.assertTrue(typeOfIntroducedProblem + "signature validation should fail", isSignatureValidationFailure(e));
            return;
        }
        Assert.fail(typeOfIntroducedProblem+"ProcessingException expected");
    }

    @Test
    public void testSignaturesRedirectBindingNegativeType2() throws Exception {
        String typeOfIntroducedProblem = "Type of problem(addFakeGoodAssertionWithoutSignature):";
        try {
            doSignatureTest(false, new DefaultSAML2HandlerConfig(), false, true, false);
        } catch (ProcessingException e) {
            Assert.assertTrue(typeOfIntroducedProblem + "signature validation should fail", isSignatureValidationFailure(e));
            return;
        }
        Assert.fail(typeOfIntroducedProblem+"ProcessingException expected");
    }

    @Test
    public void testSignaturesRedirectBindingNegativeType3() throws Exception {
        String typeOfIntroducedProblem = "Type of problem(addBadAssertionWithSignature):";
        try {
            doSignatureTest(false, new DefaultSAML2HandlerConfig(), false, false, true);
        } catch (ProcessingException e) {
            Assert.assertTrue(typeOfIntroducedProblem + "signature validation should fail", isSignatureValidationFailure(e));
            return;
        }
        Assert.fail(typeOfIntroducedProblem+"ProcessingException expected");
    }

    private void doSignatureTest(boolean isPostBinding, SAML2HandlerConfig handlerConfig,
                                 boolean addBadAssertionWithoutSignature,
                                 boolean addFakeGoodAssertionWithoutSignature,
                                 boolean addBadAssertionWithSignature) throws Exception {
        SAML2Request saml2Request = new SAML2Request();
        String id = IDGenerator.create("ID_");
        String assertionConsumerURL = "http://sp";
        String destination = "http://idp";
        String issuerValue = "http://sp";
        AuthnRequestType authnRequest = saml2Request.createAuthnRequestType(id, assertionConsumerURL, destination, issuerValue);

        Document authDoc = saml2Request.convert(authnRequest);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        KeyPair keypair = kpg.genKeyPair();

        SAML2SignatureGenerationHandler handler = new SAML2SignatureGenerationHandler();

        SAML2HandlerChainConfig chainConfig = new DefaultSAML2HandlerChainConfig();

        Map<String, Object> chainOptions = new HashMap<String, Object>();
        SPType spType = new SPType();
        chainOptions.put(GeneralConstants.CONFIGURATION, spType);
        chainOptions.put(GeneralConstants.KEYPAIR, keypair);
        chainConfig.set(chainOptions);

        // Initialize the handler
        handler.initChainConfig(chainConfig);
        handler.initHandlerConfig(handlerConfig);

        // Create a Protocol Context
        MockHttpSession session = new MockHttpSession();
        MockServletContext servletContext = new MockServletContext();
        String httpMethod = isPostBinding ? "POST" : "GET";
        MockHttpServletRequest servletRequest = new MockHttpServletRequest(session, httpMethod);
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        HTTPContext httpContext = new HTTPContext(servletRequest, servletResponse, servletContext);

        if (!isPostBinding) {
            servletRequest.addParameter(SAML_SIGNATURE_REQUEST_KEY, "");
        }

        SAMLDocumentHolder docHolder = new SAMLDocumentHolder(authnRequest, authDoc);
        IssuerInfoHolder issuerInfo = new IssuerInfoHolder("http://localhost:8080/idp/");
        SAML2HandlerRequest request = new DefaultSAML2HandlerRequest(httpContext, issuerInfo.getIssuer(), docHolder,
                SAML2Handler.HANDLER_TYPE.IDP);
        request.setTypeOfRequestToBeGenerated(GENERATE_REQUEST_TYPE.AUTH);

        SAML2HandlerResponse response = new DefaultSAML2HandlerResponse();
        response.setPostBindingForResponse(isPostBinding);

        request.addOption(GeneralConstants.SENDER_PUBLIC_KEY, keypair.getPublic());

        SAML2AuthenticationHandler authHandler = new SAML2AuthenticationHandler();
        authHandler.initChainConfig(chainConfig);
        authHandler.initHandlerConfig(handlerConfig);
        authHandler.generateSAMLRequest(request, response);

        handler.generateSAMLRequest(request, response);
        Document signedDoc = response.getResultingDocument();

        assertNotNull("Signed Doc is not null", signedDoc);
        SAMLDocumentHolder signedHolder = new SAMLDocumentHolder(signedDoc);
        request = new DefaultSAML2HandlerRequest(httpContext, issuerInfo.getIssuer(), signedHolder,
                SAML2Handler.HANDLER_TYPE.SP);

        request.addOption(GeneralConstants.SENDER_PUBLIC_KEY, keypair.getPublic());

        if (!isPostBinding) {
            servletRequest.setQueryString(response.getDestinationQueryStringWithSignature());
        }

        SAML2SignatureValidationHandler validHandler = new SAML2SignatureValidationHandler();
        validHandler.initChainConfig(chainConfig);
        validHandler.initHandlerConfig(handlerConfig);

        validHandler.handleStatusResponseType(request, response);


        // here we start to configure the IdP to generate a valid response
        PicketLinkCoreSTS.instance().installDefaultConfiguration();

        // Create chainConfig for IDP
        Map<String, Object> chainOptionsIdp = new HashMap<String, Object>();
        IDPType idpType = new IDPType();
        idpType.setSupportsSignature(true);
        idpType.setIdentityURL("http://idp");
        chainOptionsIdp.put(GeneralConstants.CONFIGURATION, idpType);
        chainOptionsIdp.put(GeneralConstants.KEYPAIR, keypair);
        SAML2HandlerChainConfig chainConfigIdp = new DefaultSAML2HandlerChainConfig(chainOptionsIdp);

        // Create and init handlers for IDP
        SAML2AuthenticationHandler idpAuthenticationHandler = new SAML2AuthenticationHandler();

        idpAuthenticationHandler.initChainConfig(chainConfigIdp);
        idpAuthenticationHandler.initHandlerConfig(handlerConfig);

        MockHttpSession idpSession = new MockHttpSession();
        MockServletContext idpServletContext = new MockServletContext();
        idpSession.setServletContext(idpServletContext);
        IdentityServer server = new IdentityServer();
        idpServletContext.setAttribute("IDENTITY_SERVER", server);
        MockHttpServletRequest idpRequest = new MockHttpServletRequest(session, httpMethod);
        MockHttpServletResponse idpResponse = new MockHttpServletResponse();
        HTTPContext idpHttpContext = new HTTPContext(idpRequest, idpResponse, idpServletContext);
        SAML2HandlerRequest idpHandlerRequest = new DefaultSAML2HandlerRequest(idpHttpContext, issuerInfo.getIssuer(), docHolder,
                SAML2Handler.HANDLER_TYPE.IDP);
        idpHandlerRequest.addOption(GeneralConstants.ASSERTIONS_VALIDITY, new Long(60 * 60 * 1000));
        SAML2HandlerResponse idpHandlerResponse = new DefaultSAML2HandlerResponse();

        // generate a valid response
        idpAuthenticationHandler.handleRequestType(idpHandlerRequest, idpHandlerResponse);

        Document validResponse = idpHandlerResponse.getResultingDocument();

        System.out.println(DocumentUtil.asString(validResponse));

        // configure a signature generation handle to sign the valid response
        SAML2SignatureGenerationHandler idpSignatureGenerationHandler = new SAML2SignatureGenerationHandler();

        chainConfig.addParameter(GeneralConstants.ROLE_VALIDATOR, new DefaultRoleValidator() {
            @Override
            public boolean userInRole(Principal userPrincipal, List<String> roles) {
                return true;
            }
        });

        idpSignatureGenerationHandler.initChainConfig(chainConfigIdp);

        handlerConfig.addParameter("SIGN_ASSERTION_ONLY", true);

        idpSignatureGenerationHandler.initHandlerConfig(handlerConfig);

        // here we sign the valid response
        idpSignatureGenerationHandler.handleStatusResponseType(idpHandlerRequest, idpHandlerResponse);

        Document signedValidResponse = idpHandlerResponse.getResultingDocument();

        System.out.println(DocumentUtil.asString(signedValidResponse));

        SAMLParser parser = new SAMLParser();
        ResponseType responseType = (ResponseType) parser.parse(DocumentUtil.getNodeAsStream(signedValidResponse));

        AssertionType assertion = responseType.getAssertions().get(0).getAssertion();

        // add an unsigned assertion
        if (addBadAssertionWithoutSignature) {
            addBadAssertionWithoutSignature(responseType);
        }

        // add fake good assertion without signature
        if (addFakeGoodAssertionWithoutSignature) {
            addFakeGoodAssertionWithoutSignature(responseType);
        }

        // add a signed assertion with an invalid signature
        if (addBadAssertionWithSignature) {
            addBadAssertionWithSignature(responseType);
        }

        Document convert = new SAML2Response().convert(responseType);

        System.out.println(DocumentUtil.asString(convert));

        SAMLDocumentHolder samlDocumentHolder = new SAMLDocumentHolder(convert);
        session = new MockHttpSession();
        servletContext = new MockServletContext();
        servletRequest = new MockHttpServletRequest(session, "POST");
        servletResponse = new MockHttpServletResponse();
        httpContext = new HTTPContext(servletRequest, servletResponse, servletContext);
        session.setServletContext(servletContext);
        samlDocumentHolder.setSamlObject(responseType);
        DefaultSAML2HandlerRequest request1 = new DefaultSAML2HandlerRequest(httpContext, assertion.getIssuer(), samlDocumentHolder,
                SAML2Handler.HANDLER_TYPE.SP);

        request1.addOption(GeneralConstants.SENDER_PUBLIC_KEY, keypair.getPublic());

        validHandler.handleStatusResponseType(request1, idpHandlerResponse);

        spType.setServiceURL("http://sp");

        authHandler.handleStatusResponseType(request1, idpHandlerResponse);

        Principal userPrincipal = (Principal) session.getAttribute(PRINCIPAL_ID);

        assertEquals("testuser", userPrincipal.getName());
    }

    private boolean isSignatureValidationFailure(ProcessingException exception) {
        Throwable cause = exception.getCause();
        return cause instanceof SignatureValidationException || cause instanceof XMLSignatureException;
    }

    private void addBadAssertionWithoutSignature(ResponseType responseType) {
        NameIDType issuer = new NameIDType();
        issuer.setValue("http://badidp");
        AssertionType assertion = AssertionUtil.createAssertion("12", issuer);
        SubjectType subject = new SubjectType();
        SubjectType.STSubType subType = new SubjectType.STSubType();
        NameIDType base = new NameIDType();

        base.setValue("bad_user");

        subType.addBaseID(base);

        subject.setSubType(subType);

        assertion.setSubject(subject);

        responseType.addAssertion(0, new ResponseType.RTChoiceType(assertion));
    }

    private void addFakeGoodAssertionWithoutSignature(ResponseType responseType) {
        NameIDType issuer = new NameIDType();
        issuer.setValue("http://localhost:8080/idp/");

        AssertionType assertion = AssertionUtil.createAssertion("12", issuer);
        SubjectType subject = new SubjectType();
        SubjectType.STSubType subType = new SubjectType.STSubType();
        NameIDType base = new NameIDType();

        base.setValue("Admin");

        subType.addBaseID(base);

        subject.setSubType(subType);

        assertion.setSubject(subject);

        responseType.addAssertion(0, new ResponseType.RTChoiceType(assertion));
    }

    private void addBadAssertionWithSignature(ResponseType responseType) throws ParsingException, ConfigurationException, ProcessingException {
        InputStream configStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("saml/v2/response/invalid-signed-assertion.xml");
        AssertionType samlObject = (AssertionType) new SAMLParser().parse(configStream);
        responseType.addAssertion(0, new ResponseType.RTChoiceType(samlObject));
    }

}