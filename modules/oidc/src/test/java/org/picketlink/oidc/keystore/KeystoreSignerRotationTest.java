package org.picketlink.oidc.keystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.issuance.RsaJwtSigningService;
import org.picketlink.auth.oauth.jwt.JwtAccessTokenIssuer;
import org.picketlink.auth.oauth.jwt.JwtAccessTokenValidator;
import org.picketlink.auth.oauth.jwt.JwtSettings;
import org.picketlink.auth.oauth.jwt.JwtSigner;
import org.picketlink.oidc.OidcKeystoreConfig;

class KeystoreSignerRotationTest {

    @Test
    void rotationFeedsTheSignerAuthAndOidcShare() throws Exception {
        Path dir = Path.of("/tmp/maketest/oidc-signer");
        Files.createDirectories(dir);
        Path keystore = dir.resolve("signing-" + System.nanoTime() + ".jks");
        String storePassword = "store-pw";
        String keyPassword = "key-pw";
        keytool(
                "-genkeypair",
                "-alias", "active",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "30",
                "-keystore", keystore.toString(),
                "-storepass", storePassword,
                "-keypass", keyPassword,
                "-dname", "CN=PicketLink OIDC Signing");

        DynamicOidcKeyStore store = DynamicOidcKeyStore.load(new OidcKeystoreConfig(
                keystore, storePassword, keyPassword, "active", "JKS"));
        JwtSigner signer = store.signer();
        JwtSettings settings = new JwtSettings("https://issuer.example", "unused", 3600L);
        JwtAccessTokenIssuer authIssuer = new JwtAccessTokenIssuer(settings, signer);
        RsaJwtSigningService oidcSigner = new RsaJwtSigningService("https://issuer.example", signer);
        Instant issuedAt = Instant.now();

        String before = authIssuer.issueToken("user1", "rda-client", Set.of("api.read"), Set.of("api"), issuedAt);
        assertTrue(header(before).contains("\"kid\":\"active\""));

        String rotatedKid = store.rotateSigningKey(30).activeAlias();
        assertNotEquals("active", rotatedKid);
        String after = authIssuer.issueToken("user1", "rda-client", Set.of("api.read"), Set.of("api"), issuedAt);
        assertTrue(header(after).contains("\"kid\":\"" + rotatedKid + "\""));
        assertTrue(signer.jwks().contains("\"kid\":\"active\""));
        assertTrue(signer.jwks().contains("\"kid\":\"" + rotatedKid + "\""));

        JwtAccessTokenValidator validator = new JwtAccessTokenValidator(
                settings, () -> issuedAt.plusSeconds(5), signer);
        assertEquals("rda-client", validator.validate(before).getClientId());
        assertEquals("rda-client", validator.validate(after).getClientId());
        assertEquals(signer.keyId(), oidcSigner.activeKeyId());
        assertTrue(oidcSigner.publicJwksJson().contains(rotatedKid));
    }

    private static String header(String token) {
        return new String(java.util.Base64.getUrlDecoder().decode(token.split("\\.")[0]));
    }

    private static void keytool(String... args) throws Exception {
        Path keytool = Path.of(System.getProperty("java.home"), "bin", "keytool");
        java.util.List<String> command = new java.util.ArrayList<>();
        command.add(keytool.toString());
        java.util.Collections.addAll(command, args);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IllegalStateException("keytool failed (" + exit + "): " + output);
        }
    }
}
