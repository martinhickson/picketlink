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
package org.picketlink.test.identity.federation.web.filters;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;

import javax.crypto.SecretKey;

import jakarta.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.config.federation.AuthPropertyType;
import org.picketlink.config.federation.KeyValueType;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.web.filters.SPFilter;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.test.identity.federation.web.mock.MockHttpServletResponse;

/**
 * The GET path posts an AuthnRequest through sendRequestToIDP. When signatures are enabled
 * that POST must carry a signature, the same as sendToDestination.
 */
public class SPFilterAuthnRequestSignatureTestCase {

    @Test
    public void signsAuthnRequestWhenSignaturesAreEnabled() throws Exception {
        String xml = postedAuthnRequest(false);
        assertTrue(xml.contains("AuthnRequest"));
        assertTrue(xml.contains("Signature"));
    }

    @Test
    public void missingKeyManagerFailsWhenSignaturesAreEnabled() throws Exception {
        ExposedFilter filter = new ExposedFilter();
        filter.setIgnoreSignatures(false);
        AuthnRequestType authnRequest = new SAML2Request().createAuthnRequestType(
                "ID_authn",
                "https://sp.example/acs",
                "https://idp.example/saml",
                "https://sp.example");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setOutputStream(new ByteArrayOutputStream());
        try {
            filter.sendRequestToIDP(authnRequest, null, response);
            fail("expected a missing signing key to fail");
        } catch (java.security.GeneralSecurityException e) {
            assertTrue(e.getMessage().contains("no signing key"));
        }
    }

    @Test
    public void leavesAuthnRequestUnsignedWhenSignaturesAreIgnored() throws Exception {
        String xml = postedAuthnRequest(true);
        assertTrue(xml.contains("AuthnRequest"));
        assertFalse(xml.contains("Signature"));
    }

    private static String postedAuthnRequest(boolean ignoreSignatures) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair keyPair = generator.generateKeyPair();

        ExposedFilter filter = new ExposedFilter();
        filter.setIgnoreSignatures(ignoreSignatures);
        Field keyManager = SPFilter.class.getDeclaredField("keyManager");
        keyManager.setAccessible(true);
        keyManager.set(filter, new SigningKeys(keyPair));

        AuthnRequestType authnRequest = new SAML2Request().createAuthnRequestType(
                "ID_authn",
                "https://sp.example/acs",
                "https://idp.example/saml",
                "https://sp.example");

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setOutputStream(body);
        filter.sendRequestToIDP(authnRequest, null, response);

        String html = body.toString(StandardCharsets.UTF_8);
        String marker = "NAME=\"" + GeneralConstants.SAML_REQUEST_KEY + "\" VALUE=\"";
        int start = html.indexOf(marker);
        assertTrue(html, start >= 0);
        int valueStart = start + marker.length();
        int valueEnd = html.indexOf('"', valueStart);
        byte[] decoded = PostBindingUtil.base64Decode(html.substring(valueStart, valueEnd));
        return new String(decoded, StandardCharsets.UTF_8);
    }

    private static final class ExposedFilter extends SPFilter {
        void setIgnoreSignatures(boolean ignoreSignatures) {
            this.ignoreSignatures = ignoreSignatures;
        }

        @Override
        public void sendRequestToIDP(AuthnRequestType authnRequest, String relayState, HttpServletResponse response)
                throws java.io.IOException, org.xml.sax.SAXException, java.security.GeneralSecurityException {
            super.sendRequestToIDP(authnRequest, relayState, response);
        }
    }

    private static final class SigningKeys implements TrustKeyManager {
        private final KeyPair keyPair;

        SigningKeys(KeyPair keyPair) {
            this.keyPair = keyPair;
        }

        @Override
        public void setAuthProperties(List<AuthPropertyType> authList) {
        }

        @Override
        public void setValidatingAlias(List<KeyValueType> aliases) {
        }

        @Override
        public PrivateKey getSigningKey() {
            return keyPair.getPrivate();
        }

        @Override
        public KeyPair getSigningKeyPair() {
            return keyPair;
        }

        @Override
        public Certificate getCertificate(String alias) {
            throw new UnsupportedOperationException();
        }

        @Override
        public PublicKey getPublicKey(String alias) {
            return keyPair.getPublic();
        }

        @Override
        public SecretKey getEncryptionKey(String domain, String encryptionAlgorithm, int keyLength) {
            throw new UnsupportedOperationException();
        }

        @Override
        public PublicKey getValidatingKey(String domain) {
            return keyPair.getPublic();
        }

        @Override
        public void addAdditionalOption(String key, Object value) {
        }

        @Override
        public Object getAdditionalOption(String key) {
            return null;
        }
    }
}
