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
package org.picketlink.identity.federation.api.util;

import org.picketlink.config.federation.ProviderType;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Security controls for SAML XML signature and redirect-binding cryptography.
 *
 * <p>When enabled, aligns with Keycloak 21+ and JDK 17+ {@code jdk.xml.dsig.secureValidationPolicy} by rejecting
 * deprecated algorithms such as {@code RSA_SHA1} and {@code DSA_SHA1}, and preferring {@code RSA_SHA256} defaults.</p>
 *
 * <p>Validation and signing policy are controlled separately via trusted {@link ProviderType} configuration:
 * {@code AcceptLegacyAlgorithms} (inbound validation) and {@code EnableLegacySigning} (outbound signing).</p>
 */
public final class SamlCryptoSecurityUtil {

    /**
     * When {@code true}, reject weak XML signature algorithms and use strong signing defaults (Keycloak/JDK 17+ aligned).
     */
    public static final boolean STRONG_CRYPTO_ENABLED = true;

    private static final ThreadLocal<Boolean> ACCEPT_LEGACY_FOR_VALIDATION = new ThreadLocal<Boolean>();
    private static final ThreadLocal<Boolean> LEGACY_SIGNING_ENABLED = new ThreadLocal<Boolean>();

    /**
     * DOM XML Signature secure validation property (JDK {@code jdk.xml.dsig.secureValidationPolicy}).
     */
    public static final String SECURE_VALIDATION_PROPERTY = "org.jcp.xml.dsig.secureValidation";

    /**
     * Algorithms disallowed by default JDK 17+ {@code jdk.xml.dsig.secureValidationPolicy} and deprecated in Keycloak SAML.
     */
    private static final Set<String> DISALLOWED_ALGORITHMS = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            "http://www.w3.org/TR/1999/REC-xslt-19991116",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
            "http://www.w3.org/2001/04/xmldsig-more#hmac-md5",
            "http://www.w3.org/2001/04/xmldsig-more#md5",
            "http://www.w3.org/2000/09/xmldsig#sha1",
            "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
    )));

    private static final String JAVA_RSA_SHA256 = "SHA256withRSA";
    private static final String JAVA_RSA_SHA1 = "SHA1withRSA";
    private static final String JAVA_DSA_SHA1 = "SHA1withDSA";

    private SamlCryptoSecurityUtil() {
    }

    public static boolean isAcceptLegacyAlgorithmsFromConfig(ProviderType providerType) {
        return providerType != null && providerType.isAcceptLegacyAlgorithms();
    }

    public static boolean isLegacySigningEnabledFromConfig(ProviderType providerType) {
        return providerType != null && providerType.isEnableLegacySigning();
    }

    public static void setAcceptLegacyAlgorithmsForValidation(boolean enabled) {
        ACCEPT_LEGACY_FOR_VALIDATION.set(enabled);
    }

    public static void setLegacySigningEnabled(boolean enabled) {
        LEGACY_SIGNING_ENABLED.set(enabled);
    }

    public static void clearValidationCryptoContext() {
        ACCEPT_LEGACY_FOR_VALIDATION.remove();
    }

    public static void clearSigningCryptoContext() {
        LEGACY_SIGNING_ENABLED.remove();
    }

    private static boolean isStrongValidationEnforced() {
        return STRONG_CRYPTO_ENABLED && !Boolean.TRUE.equals(ACCEPT_LEGACY_FOR_VALIDATION.get());
    }

    private static boolean isStrongSigningEnforced() {
        return STRONG_CRYPTO_ENABLED && !Boolean.TRUE.equals(LEGACY_SIGNING_ENABLED.get());
    }

    public static String getDefaultSignatureMethod() {
        return getSignatureMethodForSigning(false);
    }

    public static String getDefaultDigestMethod() {
        return getDigestMethodForSigning(false);
    }

    public static String getSignatureMethodForSigning(boolean legacySigningEnabled) {
        boolean strong = STRONG_CRYPTO_ENABLED && !legacySigningEnabled;
        return strong ? SignatureMethod.RSA_SHA256 : SignatureMethod.RSA_SHA1;
    }

    public static String getDigestMethodForSigning(boolean legacySigningEnabled) {
        boolean strong = STRONG_CRYPTO_ENABLED && !legacySigningEnabled;
        return strong ? DigestMethod.SHA256 : DigestMethod.SHA1;
    }

    public static String getSignatureMethodForSigning() {
        return isStrongSigningEnforced() ? SignatureMethod.RSA_SHA256 : SignatureMethod.RSA_SHA1;
    }

    public static String getDigestMethodForSigning() {
        return isStrongSigningEnforced() ? DigestMethod.SHA256 : DigestMethod.SHA1;
    }

    public static String getDefaultJavaSignatureAlgorithm(String keyAlgorithm) {
        return getJavaSignatureAlgorithmForSigning(keyAlgorithm, false);
    }

    public static String getJavaSignatureAlgorithmForSigning(String keyAlgorithm, boolean legacySigningEnabled) {
        if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            return JAVA_DSA_SHA1;
        }
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            boolean strong = STRONG_CRYPTO_ENABLED && !legacySigningEnabled;
            return strong ? JAVA_RSA_SHA256 : JAVA_RSA_SHA1;
        }
        return null;
    }

    public static String getJavaSignatureAlgorithmForSigning(String keyAlgorithm) {
        if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            return JAVA_DSA_SHA1;
        }
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            return isStrongSigningEnforced() ? JAVA_RSA_SHA256 : JAVA_RSA_SHA1;
        }
        return null;
    }

    public static String getDefaultXmlSignatureAlgorithmUri(String keyAlgorithm) {
        return getXmlSignatureAlgorithmUriForSigning(keyAlgorithm, false);
    }

    public static String getXmlSignatureAlgorithmUriForSigning(String keyAlgorithm, boolean legacySigningEnabled) {
        if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            return SignatureMethod.DSA_SHA1;
        }
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            return getSignatureMethodForSigning(legacySigningEnabled);
        }
        return null;
    }

    public static String getXmlSignatureAlgorithmUriForSigning(String keyAlgorithm) {
        if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            return SignatureMethod.DSA_SHA1;
        }
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            return getSignatureMethodForSigning();
        }
        return null;
    }

    public static void configureSecureValidation(DOMValidateContext context) {
        if (isStrongValidationEnforced()) {
            context.setProperty(SECURE_VALIDATION_PROPERTY, Boolean.TRUE);
        }
    }

    public static boolean isDisallowedAlgorithm(String algorithmUri) {
        return isStrongValidationEnforced() && algorithmUri != null && DISALLOWED_ALGORITHMS.contains(algorithmUri);
    }

    /**
     * @return {@code true} when the signature uses algorithms blocked under strong crypto policy.
     */
    public static boolean usesDisallowedAlgorithms(XMLSignature signature) {
        if (!isStrongValidationEnforced() || signature == null) {
            return false;
        }

        SignedInfo signedInfo = signature.getSignedInfo();
        if (isDisallowedAlgorithm(signedInfo.getSignatureMethod().getAlgorithm())) {
            return true;
        }

        for (Reference reference : (List<Reference>) signedInfo.getReferences()) {
            if (isDisallowedAlgorithm(reference.getDigestMethod().getAlgorithm())) {
                return true;
            }
            for (Transform transform : reference.getTransforms()) {
                if (isDisallowedAlgorithm(transform.getAlgorithm())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Maps a SAML redirect-binding {@code SigAlg} URI to a JCA signature algorithm name.
     */
    public static String toJavaSignatureAlgorithm(String xmlSignatureMethodUri) {
        if (xmlSignatureMethodUri == null) {
            return null;
        }
        if (SignatureMethod.RSA_SHA256.equals(xmlSignatureMethodUri)
                || "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1".equals(xmlSignatureMethodUri)) {
            return JAVA_RSA_SHA256;
        }
        if (SignatureMethod.RSA_SHA512.equals(xmlSignatureMethodUri)
                || "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1".equals(xmlSignatureMethodUri)) {
            return "SHA512withRSA";
        }
        if (SignatureMethod.RSA_SHA1.equals(xmlSignatureMethodUri)
                || "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1".equals(xmlSignatureMethodUri)) {
            return JAVA_RSA_SHA1;
        }
        if (SignatureMethod.DSA_SHA1.equals(xmlSignatureMethodUri)) {
            return JAVA_DSA_SHA1;
        }
        return null;
    }
}
