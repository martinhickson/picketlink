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
    private final PrivateKey privateKey;
    private final boolean ed25519;

    private SigningKey(String keyId, SignatureAlgorithm algorithm,
            JwsSignatureProvider signatureProvider, PublicKey publicKey, byte[] secret) {
        this(keyId, algorithm, signatureProvider, publicKey, secret, null, false);
    }

    private SigningKey(String keyId, SignatureAlgorithm algorithm,
            JwsSignatureProvider signatureProvider, PublicKey publicKey, byte[] secret,
            PrivateKey privateKey, boolean ed25519) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        this.algorithm = algorithm;
        this.signatureProvider = signatureProvider;
        this.publicKey = publicKey;
        this.secret = secret;
        this.privateKey = privateKey;
        this.ed25519 = ed25519;
    }

    /**
     * Ed25519 (EdDSA) key pair — signed via plain JCA ("Ed25519"), framed as JWS with
     * {@code alg: EdDSA} and published as an OKP JWK (RFC 8037). CXF 4.x has no EdDSA
     * enum, so this key type bypasses the CXF signature provider.
     */
    public static SigningKey ed25519KeyPair(String keyId, KeyPair keyPair) {
        Objects.requireNonNull(keyPair, "keyPair");
        return new SigningKey(keyId, SignatureAlgorithm.NONE, null, keyPair.getPublic(), null,
                keyPair.getPrivate(), true);
    }

    public static SigningKey forKeyPair(String keyId, KeyPair keyPair, SignatureAlgorithm algorithm) {
        Objects.requireNonNull(keyPair, "keyPair");
        // EC keys need the EC-specific provider (DER -> raw JOSE signature conversion)
        org.apache.cxf.rs.security.jose.jws.JwsSignatureProvider provider;
        if (keyPair.getPrivate() instanceof java.security.interfaces.ECPrivateKey) {
            provider = new org.apache.cxf.rs.security.jose.jws.EcDsaJwsSignatureProvider(
                    (java.security.interfaces.ECPrivateKey) keyPair.getPrivate(), algorithm);
        } else {
            provider = new PrivateKeyJwsSignatureProvider(keyPair.getPrivate(), algorithm);
        }
        return new SigningKey(keyId, algorithm, provider, keyPair.getPublic(), null);
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

    /** True for Ed25519 keys (JCA-signed, alg name "EdDSA"). */
    public boolean isEd25519() {
        return ed25519;
    }

    /** Private key material for Ed25519 keys; null otherwise. */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /** Symmetric key material; null for asymmetric keys. */
    public byte[] getSecret() {
        return secret == null ? null : secret.clone();
    }

    public boolean isPublishable() {
        return publicKey != null;
    }
}
