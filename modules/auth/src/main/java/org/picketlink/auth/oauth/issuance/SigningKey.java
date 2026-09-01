package org.picketlink.auth.oauth.issuance;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import javax.crypto.SecretKey;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jws.HmacJwsSignatureProvider;
import org.apache.cxf.rs.security.jose.jws.JwsSignatureProvider;
import org.apache.cxf.rs.security.jose.jws.PrivateKeyJwsSignatureProvider;

/**
 * A signing key known to the issuance layer. Asymmetric keys can be published through JWKS
 * (via their {@link PublicKey}); symmetric keys are never published.
 */
public final class SigningKey {

    private final String keyId;
    private final SignatureAlgorithm algorithm;
    private final JwsSignatureProvider signatureProvider;
    private final PublicKey publicKey;
    private final byte[] secret;

    private SigningKey(String keyId, SignatureAlgorithm algorithm,
            JwsSignatureProvider signatureProvider, PublicKey publicKey, byte[] secret) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.signatureProvider = Objects.requireNonNull(signatureProvider, "signatureProvider");
        this.publicKey = publicKey;
        this.secret = secret;
    }

    public static SigningKey forKeyPair(String keyId, KeyPair keyPair, SignatureAlgorithm algorithm) {
        Objects.requireNonNull(keyPair, "keyPair");
        return new SigningKey(keyId, algorithm,
                new PrivateKeyJwsSignatureProvider(keyPair.getPrivate(), algorithm),
                keyPair.getPublic(), null);
    }

    public static SigningKey forPrivateKey(String keyId, PrivateKey privateKey,
            PublicKey publicKey, SignatureAlgorithm algorithm) {
        return new SigningKey(keyId, algorithm,
                new PrivateKeyJwsSignatureProvider(privateKey, algorithm),
                publicKey, null);
    }

    public static SigningKey forSecret(String keyId, byte[] secret, SignatureAlgorithm algorithm) {
        return new SigningKey(keyId, algorithm, new HmacJwsSignatureProvider(secret, algorithm),
                null, secret.clone());
    }

    public static SigningKey forSecretKey(String keyId, SecretKey secretKey, SignatureAlgorithm algorithm) {
        return forSecret(keyId, secretKey.getEncoded(), algorithm);
    }

    public String getKeyId() {
        return keyId;
    }

    public SignatureAlgorithm getAlgorithm() {
        return algorithm;
    }

    public JwsSignatureProvider getSignatureProvider() {
        return signatureProvider;
    }

    /** May be null for symmetric keys; only asymmetric keys are publishable via JWKS. */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /** Symmetric key material; null for asymmetric keys. */
    public byte[] getSecret() {
        return secret == null ? null : secret.clone();
    }

    public boolean isPublishable() {
        return publicKey != null;
    }
}
