package org.picketlink.auth.oauth.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ConstantTimeClientSecretMatcher implements ClientSecretMatcher {

    @Override
    public boolean matches(String expectedSecret, String providedSecret) {
        if (expectedSecret == null || providedSecret == null) {
            return false;
        }
        return MessageDigest.isEqual(
                digest(expectedSecret),
                digest(providedSecret));
    }

    private static byte[] digest(String value) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is required", ex);
        }
    }
}
