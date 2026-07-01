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

import org.junit.Test;
import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.identity.federation.api.util.SamlCryptoSecurityUtil;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.api.util.XmlSignatureSecurityUtil;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.util.KeyStoreUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType.STSubType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import java.security.KeyPair;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests reference-based XML signature validation (CVE-2024-8698-class).
 */
public class XmlSignatureReferenceValidationUnitTestCase {

    @Test
    public void testReferenceValidationEnabledByDefault() {
        assertTrue(XmlSignatureSecurityUtil.REFERENCE_BASED_SIGNATURE_VALIDATION_ENABLED);
    }

    @Test
    public void testValidAssertionOnlySignatureAccepted() throws Exception {
        KeyPair keyPair = getKeyPair();
        Document signedDoc = createSignedResponseDocument(keyPair);
        assertTrue(XMLSignatureUtil.validate(signedDoc, keyPair.getPublic()));
    }

    @Test
    public void testRejectsSignatureMovedBelowResponseWithInjectedAssertion() throws Exception {
        KeyPair keyPair = getKeyPair();
        Document document = createSignedResponseDocument(keyPair);

        removeDirectResponseSignature(document);

        Element assertion = (Element) document.getElementsByTagNameNS(
                JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.ASSERTION.get()).item(0);
        Element signature = (Element) assertion.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
        assertion.removeChild(signature);
        document.getDocumentElement().appendChild(signature);

        Element evilAssertion = (Element) assertion.cloneNode(true);
        evilAssertion.setAttribute("ID", "_evil_assertion_ID");
        NodeList evilSignatures = evilAssertion.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        for (int i = evilSignatures.getLength() - 1; i >= 0; i--) {
            evilAssertion.removeChild(evilSignatures.item(i));
        }
        document.getDocumentElement().insertBefore(evilAssertion, assertion);

        assertFalse(XMLSignatureUtil.validate(document, keyPair.getPublic()));
    }

    private Document createSignedResponseDocument(KeyPair keyPair) throws Exception {
        IssuerInfoHolder issuerInfo = new IssuerInfoHolder("testIssuer");
        SAML2Response response = new SAML2Response();

        AssertionType assertion = response.createAssertion(IDGenerator.create("ID_"), issuerInfo.getIssuer());
        SubjectType subject = new SubjectType();
        STSubType subType = new STSubType();
        NameIDType nameId = new NameIDType();
        nameId.setValue("testuser");
        subType.addBaseID(nameId);
        subject.setSubType(subType);
        assertion.setSubject(subject);
        assertion.addStatement(response.createAuthnStatement(
                JBossSAMLURIConstants.AC_PASSWORD_PROTECTED_TRANSPORT.get(), XMLTimeUtil.getIssueInstant()));

        ResponseType responseType = response.createResponseType(IDGenerator.create("ID_"), issuerInfo, assertion);
        Document document = response.convert(responseType);

        Element assertionElement = (Element) document.getElementsByTagNameNS(
                JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.ASSERTION.get()).item(0);
        assertionElement.setIdAttribute("ID", true);
        String referenceURI = "#" + assertionElement.getAttribute("ID");
        Node nextSibling = assertionElement.getElementsByTagNameNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(),
                JBossSAMLConstants.ISSUER.get()).item(0).getNextSibling();
        XMLSignatureUtil.sign(assertionElement, nextSibling, keyPair, SamlCryptoSecurityUtil.getDefaultDigestMethod(),
                SamlCryptoSecurityUtil.getDefaultSignatureMethod(), referenceURI);

        return document;
    }

    private void removeDirectResponseSignature(Document document) {
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

    private KeyPair getKeyPair() throws Exception {
        return KeyStoreUtil.generateKeyPair("RSA");
    }
}
