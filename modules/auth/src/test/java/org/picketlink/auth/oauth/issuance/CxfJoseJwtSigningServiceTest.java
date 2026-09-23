package org.picketlink.auth.oauth.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.jwt.JwtValidationException;

class CxfJoseJwtSigningServiceTest {

    private static final String ISSUER = "https://auth.example.test";

    private static KeyPair rsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static JwtClaims claims(long issuedAt, long expiresAt) {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setSubject("rest-client");
        claims.setIssuedAt(issuedAt);
        claims.setExpiryTime(expiresAt);
        claims.setTokenId("token-1");
        return claims;
    }

    private static CxfJoseJwtSigningService service(SigningKey key, Clock clock) {
        return new CxfJoseJwtSigningService(ISSUER, List.of(key), key.getKeyId(), clock);
    }

    @Test
    void shouldSignAndValidateRs256Token() {
        SigningKey key = SigningKey.forKeyPair("key-1", rsaKeyPair(), SignatureAlgorithm.RS256);
        CxfJoseJwtSigningService signingService = service(key, Clock.systemUTC());

        long now = Instant.now().getEpochSecond();
        String token = signingService.sign(claims(now, now + 60), "RS256");

        JwtClaims verified = signingService.validate(token, Set.of("RS256"));
        assertEquals(ISSUER, verified.getIssuer());
        assertEquals("rest-client", verified.getSubject());
        assertEquals("token-1", verified.getTokenId());
    }

    @Test
    void shouldSignAndValidateHs256Token() {
        SigningKey key = SigningKey.forSecret("secret-1",
                "0123456789abcdef0123456789abcdef".getBytes(), SignatureAlgorithm.HS256);
        CxfJoseJwtSigningService signingService = service(key, Clock.systemUTC());

        long now = Instant.now().getEpochSecond();
        String token = signingService.sign(claims(now, now + 60), "HS256");
        assertNotNull(signingService.validate(token, Set.of("HS256")));
    }

    @Test
    void shouldRejectTokenSignedWithDifferentKey() {
        CxfJoseJwtSigningService otherService = service(
                SigningKey.forKeyPair("other", rsaKeyPair(), SignatureAlgorithm.RS256), Clock.systemUTC());
        long now = Instant.now().getEpochSecond();
        String foreignToken = otherService.sign(claims(now, now + 60), "RS256");

        CxfJoseJwtSigningService signingService = service(
                SigningKey.forKeyPair("mine", rsaKeyPair(), SignatureAlgorithm.RS256), Clock.systemUTC());
        assertThrows(JwtValidationException.class,
                () -> signingService.validate(foreignToken, Set.of("RS256")));
    }

    @Test
    void shouldRejectExpiredToken() {
        SigningKey key = SigningKey.forKeyPair("key-1", rsaKeyPair(), SignatureAlgorithm.RS256);
        Clock now = Clock.fixed(Instant.ofEpochSecond(10_000), ZoneOffset.UTC);
        CxfJoseJwtSigningService signingService = service(key, now);

        String token = signingService.sign(claims(9_000, 9_999), "RS256");
        JwtValidationException ex = assertThrows(JwtValidationException.class,
                () -> signingService.validate(token, Set.of("RS256")));
        assertTrue(ex.getMessage().contains("expired"));
    }

    @Test
    void shouldRejectTokenWithNotAcceptedAlgorithm() {
        SigningKey key = SigningKey.forKeyPair("key-1", rsaKeyPair(), SignatureAlgorithm.RS256);
        CxfJoseJwtSigningService signingService = service(key, Clock.systemUTC());
        long now = Instant.now().getEpochSecond();
        String token = signingService.sign(claims(now, now + 60), "RS256");

        assertThrows(JwtValidationException.class,
                () -> signingService.validate(token, Set.of("ES256")));
    }

    @Test
    void shouldKeepRotatedKeyVerifiableAndSwitchSigningKey() {
        KeyPair originalPair = rsaKeyPair();
        SigningKey original = SigningKey.forKeyPair("key-1", originalPair, SignatureAlgorithm.RS256);
        CxfJoseJwtSigningService signingService = service(original, Clock.systemUTC());

        long now = Instant.now().getEpochSecond();
        String oldToken = signingService.sign(claims(now, now + 3_600), "RS256");

        SigningKey rotated = SigningKey.forKeyPair("key-2", rsaKeyPair(), SignatureAlgorithm.RS256);
        signingService.addKey(rotated);
        signingService.setActiveKeyId("key-2");

        assertEquals("key-2", signingService.activeKeyId());
        // overlap window: token signed with the retired key must still validate
        assertNotNull(signingService.validate(oldToken, Set.of("RS256")));
        // and the JWKS must publish both keys
        String jwks = signingService.publicJwksJson();
        assertTrue(jwks.contains("key-1"));
        assertTrue(jwks.contains("key-2"));
        assertTrue(jwks.contains("\"kty\":\"RSA\""));
    }

    @Test
    void shouldPublishRsaModulusAndExponent() throws Exception {
        KeyPair pair = rsaKeyPair();
        SigningKey key = SigningKey.forKeyPair("key-1", pair, SignatureAlgorithm.RS256);
        String jwks = service(key, Clock.systemUTC()).publicJwksJson();

        RSAPublicKey rsa = (RSAPublicKey) pair.getPublic();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        assertTrue(jwks.contains(encoder.encodeToString(unsigned(rsa.getModulus()))));
        assertTrue(jwks.contains(encoder.encodeToString(unsigned(rsa.getPublicExponent()))));
        byte[] modulus = Base64.getUrlDecoder().decode(jwkMember(jwks, "n"));
        assertEquals(rsa.getModulus(), new BigInteger(1, modulus));
        assertTrue(modulus.length == 0 || modulus[0] != 0);
    }

    @Test
    void shouldPublishEcCoordinatesAtFieldWidth() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        java.security.KeyPair pair = generator.generateKeyPair();
        SigningKey key = SigningKey.forKeyPair("ec-1", pair, SignatureAlgorithm.ES256);
        String jwks = service(key, Clock.systemUTC()).publicJwksJson();

        byte[] x = Base64.getUrlDecoder().decode(jwkMember(jwks, "x"));
        byte[] y = Base64.getUrlDecoder().decode(jwkMember(jwks, "y"));
        assertEquals(32, x.length);
        assertEquals(32, y.length);
        java.security.interfaces.ECPublicKey ec =
                (java.security.interfaces.ECPublicKey) pair.getPublic();
        assertEquals(ec.getW().getAffineX(), new BigInteger(1, x));
        assertEquals(ec.getW().getAffineY(), new BigInteger(1, y));
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static String jwkMember(String jwks, String name) {
        String marker = "\"" + name + "\":\"";
        int start = jwks.indexOf(marker);
        if (start < 0) {
            throw new AssertionError("missing " + name);
        }
        start += marker.length();
        return jwks.substring(start, jwks.indexOf('"', start));
    }

    @Test
    void shouldRejectTamperedPayload() {
        SigningKey key = SigningKey.forKeyPair("key-1", rsaKeyPair(), SignatureAlgorithm.RS256);
        CxfJoseJwtSigningService signingService = service(key, Clock.systemUTC());
        long now = Instant.now().getEpochSecond();
        String token = signingService.sign(claims(now, now + 60), "RS256");

        String[] parts = token.split("\\.");
        String tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"iss\":\"https://attacker\",\"exp\":9999999999}".getBytes())
                + "." + parts[2];
        assertThrows(JwtValidationException.class,
                () -> signingService.validate(tampered, Set.of("RS256")));
    }
}
