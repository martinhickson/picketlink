/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2026 Red Hat, Inc. and/or its affiliates.
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
package org.picketlink.test.identity.federation;

import org.picketlink.config.federation.ProviderType;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.api.saml.v2.sig.SAML2Signature;
import org.picketlink.identity.federation.api.util.SamlCryptoSecurityUtil;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Enables legacy SAML crypto policy in unit tests that exercise deprecated algorithms.
 */
public final class LegacyCryptoTestSupport {

    private static final int LEGACY_DSA_KEY_SIZE = 1024;

    private LegacyCryptoTestSupport() {
    }

    public static void enableLegacyCrypto() {
        SamlCryptoSecurityUtil.setAcceptLegacyAlgorithmsForValidation(true);
        SamlCryptoSecurityUtil.setLegacySigningEnabled(true);
    }

    public static void clearLegacyCrypto() {
        SamlCryptoSecurityUtil.clearValidationCryptoContext();
        SamlCryptoSecurityUtil.clearSigningCryptoContext();
    }

    public static void runWithLegacyCrypto(LegacyCryptoCallback callback) throws Exception {
        enableLegacyCrypto();
        try {
            callback.run();
        } finally {
            clearLegacyCrypto();
        }
    }

    public interface LegacyCryptoCallback {
        void run() throws Exception;
    }

    public static SPType legacyServiceProvider() {
        SPType spType = new SPType();
        configureLegacyProvider(spType);
        return spType;
    }

    public static void configureLegacyProvider(ProviderType providerType) {
        providerType.setAcceptLegacyAlgorithms(true);
        providerType.setEnableLegacySigning(true);
    }

    public static KeyPair generateLegacyDsaKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(LEGACY_DSA_KEY_SIZE);
        return keyPairGenerator.genKeyPair();
    }

    public static SAML2Signature newLegacyDsaSignature() {
        SAML2Signature signature = new SAML2Signature();
        signature.setSignatureMethod(SignatureMethod.DSA_SHA1);
        signature.setDigestMethod(DigestMethod.SHA1);
        return signature;
    }
}
