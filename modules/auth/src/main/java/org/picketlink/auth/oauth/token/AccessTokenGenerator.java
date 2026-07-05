package org.picketlink.auth.oauth.token;

import java.security.SecureRandom;
import java.util.Base64;

public class AccessTokenGenerator {

    private final SecureRandom secureRandom = new SecureRandom();
    private final int byteLength;

    public AccessTokenGenerator() {
        this(32);
    }

    public AccessTokenGenerator(int byteLength) {
        if (byteLength < 16) {
            throw new IllegalArgumentException("byteLength must be at least 16");
        }
        this.byteLength = byteLength;
    }

    public String generate() {
        byte[] bytes = new byte[byteLength];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
