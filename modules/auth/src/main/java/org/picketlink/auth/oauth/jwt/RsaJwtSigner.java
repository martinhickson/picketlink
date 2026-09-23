package org.picketlink.auth.oauth.jwt;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public final class RsaJwtSigner implements JwtSigner {

    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

    private final String keyId;
    private final KeyPair keyPair;

    public RsaJwtSigner(String keyId) {
        this(keyId, generate());
    }

    public RsaJwtSigner(String keyId, KeyPair keyPair) {
        this.keyId = keyId;
        this.keyPair = keyPair;
    }

    @Override
    public String algorithm() {
        return "RS256";
    }

    @Override
    public String keyId() {
        return keyId;
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(signingInput);
            return signature.sign();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to sign JWT", ex);
        }
    }

    @Override
    public boolean verify(byte[] signingInput, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(keyPair.getPublic());
            signature.update(signingInput);
            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

    public String jwk() {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        return "{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\""
                + keyId + "\",\"n\":\"" + URL.encodeToString(unsigned(publicKey.getModulus()))
                + "\",\"e\":\"" + URL.encodeToString(unsigned(publicKey.getPublicExponent())) + "\"}";
    }

    @Override
    public String jwks() {
        return "{\"keys\":[" + jwk() + "]}";
    }

    public static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to generate RSA key", ex);
        }
    }

    public String signContent(String content) {
        return URL.encodeToString(sign(content.getBytes(StandardCharsets.UTF_8)));
    }
}
