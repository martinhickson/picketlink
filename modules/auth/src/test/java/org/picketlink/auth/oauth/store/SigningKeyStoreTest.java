package org.picketlink.auth.oauth.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigningKeyStoreTest {

    private static final String ISSUER = "https://auth.example.test";

    @TempDir
    Path tempDir;

    @Test
    void shouldInitializeRotateAndKeepOverlapWindow() throws Exception {
        System.setProperty(SigningKeyStore.SYSTEM_KEYSTORE_PATH,
                tempDir.resolve("test-keys.p12").toString());
        try {
            shouldInitializeRotateAndKeepOverlapWindow0();
        } finally {
            System.clearProperty(SigningKeyStore.SYSTEM_KEYSTORE_PATH);
        }
    }

    private void shouldInitializeRotateAndKeepOverlapWindow0() throws Exception {
        JdbcClobDocumentStore documentStore = new JdbcClobDocumentStore(
                new DriverManagerConnectionSource("jdbc:sqlite:" + tempDir.resolve("keys.db"), null, null));
        documentStore.save(SigningKeyStore.DOCUMENT_ID,
                SigningKeyDocument.fromJson("").toJson(), 0L);
        SigningKeyStore keyStore = new SigningKeyStore(documentStore);

        // first start: no keys yet -> rotate generates the initial key
        String firstKeyId = keyStore.rotate();
        org.picketlink.auth.oauth.issuance.JwtSigningService service = keyStore.toSigningService(ISSUER);
        assertEquals(firstKeyId, service.activeKeyId());

        long now = System.currentTimeMillis() / 1000;
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setSubject("rest-client");
        claims.setIssuedAt(now);
        claims.setExpiryTime(now + 3600);
        String oldToken = service.sign(claims, "RS256");

        // rotate: a new active key appears, the old key must keep validating (overlap window)
        String secondKeyId = keyStore.rotate();
        org.picketlink.auth.oauth.issuance.JwtSigningService rotated = keyStore.toSigningService(ISSUER);
        assertEquals(secondKeyId, rotated.activeKeyId());
        assertNotNull(rotated.validate(oldToken, java.util.Set.of("RS256")));

        // both keys published via JWKS, private material only in the keystore file
        String jwks = rotated.publicJwksJson();
        assertTrue(jwks.contains(firstKeyId));
        assertTrue(jwks.contains(secondKeyId));
        SigningKeyDocument document = keyStore.loadDocument();
        assertEquals(2, document.getKeys().size());
        assertTrue(Files.isRegularFile(Path.of(document.getKeystorePath())));

        // activate = rollback within the overlap window
        keyStore.activate(firstKeyId);
        assertEquals(firstKeyId, keyStore.toSigningService(ISSUER).activeKeyId());
        assertNotNull(keyStore.toSigningService(ISSUER).validate(oldToken, java.util.Set.of("RS256")));
    }

    @Test
    void signingKeyDocumentShouldRoundTripAsJson() {
        SigningKeyDocument document = new SigningKeyDocument();
        document.setKeystorePath("/etc/keys.p12");
        document.setActiveKid("key-2");
        document.getKeys().add(new SigningKeyRecord("key-1", "RS256", "key-1", false, 1000L));
        document.getKeys().add(new SigningKeyRecord("key-2", "RS256", "key-2", true, 2000L));

        SigningKeyDocument loaded = SigningKeyDocument.fromJson(document.toJson());
        assertEquals("/etc/keys.p12", loaded.getKeystorePath());
        assertEquals("key-2", loaded.getActiveKid());
        assertEquals(2, loaded.getKeys().size());
        assertEquals("key-1", loaded.getKeys().get(0).getKeyId());
        assertTrue(loaded.getKeys().get(1).isActive());
        assertEquals(2000L, loaded.getKeys().get(1).getCreatedAtEpochSeconds());
    }
}
