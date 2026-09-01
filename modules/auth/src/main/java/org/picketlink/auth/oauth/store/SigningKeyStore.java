package org.picketlink.auth.oauth.store;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.picketlink.auth.oauth.issuance.CxfJoseJwtSigningService;
import org.picketlink.auth.oauth.issuance.SigningKey;

/**
 * Loads signing keys referenced by the persisted {@link SigningKeyDocument} from a Java
 * keystore, and rotates them: generates a new RSA keypair directly into the keystore, appends
 * the metadata record and flips the active key. Previously rotated keys stay verifiable until
 * removed, preserving the Phase-1 overlap-window guarantee.
 */
public final class SigningKeyStore {

    public static final String DOCUMENT_ID = "keys";
    public static final String KEYSTORE_TYPE = "PKCS12";
    public static final String SYSTEM_KEYSTORE_PASSWORD = "picketlink.auth.keystore.password";
    public static final String SYSTEM_KEYSTORE_PATH = "picketlink.auth.keystore.path";
    public static final String DEFAULT_KEYSTORE_PATH = "picketlink-auth-keys.p12";

    private final JsonDocumentStore documentStore;

    public SigningKeyStore(JsonDocumentStore documentStore) {
        this.documentStore = documentStore;
    }

    public SigningKeyDocument loadDocument() {
        return SigningKeyDocument.fromJson(documentStore.load(DOCUMENT_ID));
    }

    public void saveDocument(SigningKeyDocument document) {
        long version = documentStore.currentVersion(DOCUMENT_ID);
        documentStore.save(DOCUMENT_ID, document.toJson(), version);
    }

    /**
     * Builds a signing service from the persisted document, resolving private keys from the
     * keystore referenced by {@code keystorePath} (password from the
     * {@code picketlink.auth.keystore.password} system property or environment).
     */
    public CxfJoseJwtSigningService toSigningService(String issuer) throws Exception {
        SigningKeyDocument document = loadDocument();
        if (document.getKeys().isEmpty()) {
            throw new IllegalStateException("No signing keys configured (document '" + DOCUMENT_ID + "')");
        }
        KeyStore keystore = loadKeystore(document.getKeystorePath());
        List<SigningKey> keys = new ArrayList<>();
        for (SigningKeyRecord record : document.getKeys()) {
            PrivateKey privateKey = (PrivateKey) keystore.getKey(record.getKeystoreAlias(),
                    keystorePassword());
            if (privateKey == null) {
                throw new IllegalStateException(
                        "Keystore alias '" + record.getKeystoreAlias() + "' not found");
            }
            Certificate certificate = keystore.getCertificate(record.getKeystoreAlias());
            PublicKey publicKey = certificate != null ? certificate.getPublicKey() : null;
            keys.add(SigningKey.forPrivateKey(record.getKeyId(), privateKey, publicKey,
                    SignatureAlgorithm.valueOf(record.getAlgorithm())));
        }
        return new CxfJoseJwtSigningService(issuer, keys, document.getActiveKid());
    }

    /**
     * Generates a new RSA-2048 keypair into the keystore, records it and makes it active.
     *
     * @return the new key id
     */
    public String rotate() throws Exception {
        SigningKeyDocument document = loadDocument();
        String keystorePath = document.getKeystorePath();
        if (keystorePath == null || keystorePath.isBlank()) {
            keystorePath = System.getProperty(SYSTEM_KEYSTORE_PATH, DEFAULT_KEYSTORE_PATH);
            document.setKeystorePath(keystorePath);
        }
        Path path = Path.of(keystorePath);
        KeyStore keystore = loadKeystore(keystorePath);

        String keyId = "pl-signing-" + Long.toHexString(System.nanoTime());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        java.security.KeyPair keyPair = generator.generateKeyPair();
        java.security.cert.X509Certificate certificate = SelfSignedCertificate.create(
                keyPair, "CN=PicketLink Signing " + keyId, 3650);
        keystore.setKeyEntry(keyId, keyPair.getPrivate(), keystorePassword(),
                new Certificate[] {certificate});
        try (OutputStream out = Files.newOutputStream(path)) {
            keystore.store(out, keystorePassword());
        }

        for (int i = 0; i < document.getKeys().size(); i++) {
            SigningKeyRecord record = document.getKeys().get(i);
            if (record.getKeyId().equals(document.getActiveKid())) {
                document.getKeys().set(i, new SigningKeyRecord(record.getKeyId(),
                        record.getAlgorithm(), record.getKeystoreAlias(), false,
                        record.getCreatedAtEpochSeconds()));
                break;
            }
        }
        document.getKeys().add(new SigningKeyRecord(keyId, "RS256", keyId, true,
                Instant.now().getEpochSecond()));
        document.setActiveKid(keyId);
        saveDocument(document);
        return keyId;
    }

    /** Activates an existing key (e.g. rolling back a rotation within the overlap window). */
    public void activate(String keyId) {
        SigningKeyDocument document = loadDocument();
        boolean found = false;
        List<SigningKeyRecord> updated = new ArrayList<>();
        for (SigningKeyRecord record : document.getKeys()) {
            if (record.getKeyId().equals(keyId)) {
                found = true;
            }
            updated.add(new SigningKeyRecord(record.getKeyId(), record.getAlgorithm(),
                    record.getKeystoreAlias(), record.getKeyId().equals(keyId),
                    record.getCreatedAtEpochSeconds()));
        }
        if (!found) {
            throw new IllegalArgumentException("Unknown signing key: " + keyId);
        }
        document.setActiveKid(keyId);
        document.getKeys().clear();
        document.getKeys().addAll(updated);
        saveDocument(document);
    }

    private static KeyStore loadKeystore(String keystorePath) throws Exception {
        KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
        if (keystorePath == null || !Files.isRegularFile(Path.of(keystorePath))) {
            keystore.load(null, null);
            return keystore;
        }
        try (InputStream in = Files.newInputStream(Path.of(keystorePath))) {
            keystore.load(in, keystorePassword());
        }
        return keystore;
    }

    static char[] keystorePassword() {
        String password = System.getProperty(SYSTEM_KEYSTORE_PASSWORD,
                System.getenv("PICKETLINK_KEYSTORE_PASSWORD"));
        return (password == null || password.isBlank() ? "changeit" : password).toCharArray();
    }
}
