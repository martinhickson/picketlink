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
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.identity.federation.api.util.SamlCryptoSecurityUtil;
import org.picketlink.identity.federation.core.util.KeyStoreUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import java.io.InputStream;
import java.security.KeyPair;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests strong SAML crypto policy (Keycloak/JDK 17+ aligned).
 */
public class SamlCryptoSecurityUnitTestCase {

    @Test
    public void testStrongCryptoEnabledByDefault() {
        assertTrue(SamlCryptoSecurityUtil.STRONG_CRYPTO_ENABLED);
        assertTrue(SamlCryptoSecurityUtil.isDisallowedAlgorithm(SignatureMethod.RSA_SHA1));
        assertTrue(SamlCryptoSecurityUtil.isDisallowedAlgorithm(SignatureMethod.DSA_SHA1));
        assertTrue(SamlCryptoSecurityUtil.isDisallowedAlgorithm(DigestMethod.SHA1));
        assertFalse(SamlCryptoSecurityUtil.isDisallowedAlgorithm(SignatureMethod.RSA_SHA256));
        assertFalse(SamlCryptoSecurityUtil.isDisallowedAlgorithm(DigestMethod.SHA256));
    }

    @Test
    public void testDefaultAlgorithmsAreStrong() {
        assertTrue(SignatureMethod.RSA_SHA256.equals(SamlCryptoSecurityUtil.getDefaultSignatureMethod()));
        assertTrue(DigestMethod.SHA256.equals(SamlCryptoSecurityUtil.getDefaultDigestMethod()));
    }

    @Test
    public void testRejectsWeakRsaSha1Signature() throws Exception {
        KeyPair keyPair = KeyStoreUtil.generateKeyPair("RSA");
        Document document = loadAssertionDocument();
        Element tokenElement = (Element) document.getFirstChild();
        document = XMLSignatureUtil.sign(document, tokenElement, keyPair, DigestMethod.SHA1, SignatureMethod.RSA_SHA1, "");

        assertFalse(XMLSignatureUtil.validate(document, keyPair.getPublic()));
    }

    @Test
    public void testAcceptsStrongRsaSha256Signature() throws Exception {
        KeyPair keyPair = KeyStoreUtil.generateKeyPair("RSA");
        Document document = loadAssertionDocument();
        Element tokenElement = (Element) document.getFirstChild();
        document = XMLSignatureUtil.sign(document, tokenElement, keyPair, DigestMethod.SHA256, SignatureMethod.RSA_SHA256, "");

        assertTrue(XMLSignatureUtil.validate(document, keyPair.getPublic()));
    }

    @Test
    public void testAcceptsWeakRsaSha1SignatureWhenLegacyValidationEnabled() throws Exception {
        KeyPair keyPair = KeyStoreUtil.generateKeyPair("RSA");
        Document document = loadAssertionDocument();
        Element tokenElement = (Element) document.getFirstChild();
        document = XMLSignatureUtil.sign(document, tokenElement, keyPair, DigestMethod.SHA1, SignatureMethod.RSA_SHA1, "");

        SamlCryptoSecurityUtil.setAcceptLegacyAlgorithmsForValidation(true);
        try {
            assertTrue(XMLSignatureUtil.validate(document, keyPair.getPublic()));
        } finally {
            SamlCryptoSecurityUtil.clearValidationCryptoContext();
        }
    }

    @Test
    public void testLegacyValidationDoesNotEnableLegacySigningByDefault() throws Exception {
        SamlCryptoSecurityUtil.setAcceptLegacyAlgorithmsForValidation(true);
        try {
            assertTrue(SignatureMethod.RSA_SHA256.equals(SamlCryptoSecurityUtil.getSignatureMethodForSigning()));
            assertTrue(DigestMethod.SHA256.equals(SamlCryptoSecurityUtil.getDigestMethodForSigning()));
        } finally {
            SamlCryptoSecurityUtil.clearValidationCryptoContext();
        }
    }

    @Test
    public void testLegacySigningUsesWeakAlgorithms() throws Exception {
        SamlCryptoSecurityUtil.setLegacySigningEnabled(true);
        try {
            assertTrue(SignatureMethod.RSA_SHA1.equals(SamlCryptoSecurityUtil.getSignatureMethodForSigning()));
            assertTrue(DigestMethod.SHA1.equals(SamlCryptoSecurityUtil.getDigestMethodForSigning()));
        } finally {
            SamlCryptoSecurityUtil.clearSigningCryptoContext();
        }
    }

    private Document loadAssertionDocument() throws Exception {
        String fileName = "signatures/saml11assertion.xml";
        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
        if (is == null) {
            throw new RuntimeException("InputStream is null");
        }
        return DocumentUtil.getDocument(is);
    }
}
