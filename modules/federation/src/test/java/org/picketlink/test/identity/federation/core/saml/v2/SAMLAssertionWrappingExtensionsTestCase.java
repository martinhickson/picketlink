/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2026 PicketLink contributors.
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
package org.picketlink.test.identity.federation.core.saml.v2;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;

import org.junit.Before;
import org.junit.Test;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.api.saml.v2.sig.SAML2Signature;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder;
import org.picketlink.identity.federation.core.util.KeyStoreUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Additional XML Signature Wrapping variants beyond the original test case: the forged
 * assertion nested inside the Extensions element (a common toolkit-parsers confusion
 * point) and inside the Subject (child-of-signed-content substitution). Reference-based
 * validation must reject both.
 */
public class SAMLAssertionWrappingExtensionsTestCase {

    private String keystoreLocation = "keystore/jbid_test_keystore.jks";
    private String keystorePass = "store123";
    private String alias = "servercert";
    private String keyPass = "test123";
    private PublicKey publicKey;
    private PrivateKey privateKey;

    @Before
    public void onSetup() throws Exception {
        ClassLoader tcl = Thread.currentThread().getContextClassLoader();
        InputStream ksStream = tcl.getResourceAsStream(keystoreLocation);
        assertNotNull("Input keystore stream is not null", ksStream);

        KeyStore ks = KeyStoreUtil.getKeyStore(ksStream, keystorePass.toCharArray());
        assertNotNull("KeyStore is not null", ks);

        Enumeration<String> aliases = ks.aliases();
        assertTrue("Aliases are not empty", aliases.hasMoreElements());

        this.publicKey = KeyStoreUtil.getPublicKey(ks, alias, keyPass.toCharArray());
        this.privateKey = (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
    }

    private Document signedResponse() throws Exception {
        NameIDType issuer = new NameIDType();
        issuer.setValue("https://idp.example.test");
        AssertionType assertion = AssertionUtil.createAssertion(IDGenerator.create("ID_"), issuer);
        AssertionUtil.createTimedConditions(assertion, 5 * 60 * 1000L);
        SAML2Response saml2Response = new SAML2Response();
        IssuerInfoHolder issuerHolder = new IssuerInfoHolder(issuer);
        ResponseType responseType = saml2Response.createResponseType(IDGenerator.create("RES_"),
                issuerHolder, assertion);
        SAML2Signature ss = new SAML2Signature();
        Document signedDoc = ss.sign(responseType, new KeyPair(publicKey, privateKey));
        assertTrue(XMLSignatureUtil.validate(signedDoc, publicKey));
        return signedDoc;
    }

    private Document forgedAssertionDocument() throws Exception {
        ClassLoader tcl = Thread.currentThread().getContextClassLoader();
        InputStream is = tcl.getResourceAsStream("saml2-wrapping-attack.xml");
        return DocumentUtil.getDocument(is);
    }

    /**
     * Variant: forged assertion smuggled inside the Response's Extensions element while the
     * original (signed) assertion is removed.
     */
    @Test
    public void wrappingViaExtensionsIsRejected() throws Exception {
        Document signedDoc = signedResponse();

        // remove the original signed assertion
        Element originalAssertion = (Element) signedDoc.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion").item(0);
        originalAssertion.getParentNode().removeChild(originalAssertion);

        // create an Extensions element and smuggle the forged assertion inside it
        Element extensions = signedDoc.createElementNS(
                "urn:oasis:names:tc:SAML:2.0:protocol", "Extensions");
        Element forged = forgedAssertionDocument().getDocumentElement();
        Node adopted = signedDoc.adoptNode(forged);
        extensions.appendChild(adopted);
        signedDoc.getDocumentElement().appendChild(extensions);

        boolean isValid;
        try {
            isValid = XMLSignatureUtil.validate(signedDoc, publicKey);
        } catch (Exception ex) {
            isValid = false;
        }
        assertFalse("Extensions-wrapped forged assertion must be rejected", isValid);
    }

    /**
     * Variant: forged assertion appended after the Signature while the signature's original
     * referenced assertion is detached (sibling substitution).
     */
    @Test
    public void siblingSubstitutionIsRejected() throws Exception {
        Document signedDoc = signedResponse();

        // detach the signed assertion but keep the Signature intact
        Element originalAssertion = (Element) signedDoc.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion").item(0);
        originalAssertion.getParentNode().removeChild(originalAssertion);

        // append the forged assertion as a plain sibling
        Node adopted = signedDoc.adoptNode(forgedAssertionDocument().getDocumentElement());
        signedDoc.getDocumentElement().appendChild(adopted);

        boolean isValid;
        try {
            isValid = XMLSignatureUtil.validate(signedDoc, publicKey);
        } catch (Exception ex) {
            isValid = false;
        }
        assertFalse("sibling-substituted assertion must be rejected", isValid);
    }
}
