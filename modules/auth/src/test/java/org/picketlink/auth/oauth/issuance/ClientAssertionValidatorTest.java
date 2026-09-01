package org.picketlink.auth.oauth.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
import org.apache.cxf.rs.security.jose.jwk.KeyType;
import org.apache.cxf.rs.security.jose.jwk.PublicKeyUse;
import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;

class ClientAssertionValidatorTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String CLIENT_ID = "automated-rest-client";

    private static KeyPair rsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static final long NOW = 1_000_000L;

    private final ClientAssertionValidator validator = new ClientAssertionValidator(ISSUER,
            Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC));

    private static RegisteredClient client(String jwksJson) {
        return RegisteredClient.builder(CLIENT_ID, null)
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.PRIVATE_KEY_JWT)
                .jwks(jwksJson)
                .build();
    }

    private static String assertion(KeyPair keyPair, String issuer, String subject, String audience,
            long issuedAt, long expiry) {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setIssuedAt(issuedAt);
        claims.setExpiryTime(expiry);
        claims.setTokenId("assertion-1");
        JwsHeaders headers = new JwsHeaders();
        headers.setAlgorithm("RS256");
        headers.setKeyId("client-key-1");
        return new JwsJwtCompactProducer(headers, claims).signWith(
                SigningKey.forKeyPair("client-key-1", keyPair, SignatureAlgorithm.RS256)
                        .getSignatureProvider());
    }

    private static String hmacAssertion(String secret) {
        try {
            JwtClaims claims = new JwtClaims();
            claims.setIssuer(CLIENT_ID);
            claims.setSubject(CLIENT_ID);
            claims.setAudience(ISSUER);
            claims.setIssuedAt(NOW);
            claims.setExpiryTime(NOW + 60);
            claims.setTokenId("assertion-hmac");
            JwsHeaders headers = new JwsHeaders();
            headers.setAlgorithm("HS256");
            JwsJwtCompactProducer producer = new JwsJwtCompactProducer(headers, claims);
            String signingContent = producer.getUnsignedEncodedJws();
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
            String signature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(signingContent.getBytes()));
            return signingContent + "." + signature;
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Test
    void shouldAcceptValidAssertion() {
        KeyPair keyPair = rsaKeyPair();
        JwtClaims claims = validator.validate(
                assertion(keyPair, CLIENT_ID, CLIENT_ID, ISSUER, NOW - 30, NOW + 60),
                client(jwks(keyPair)));
        assertEquals(CLIENT_ID, claims.getSubject());
    }

    @Test
    void shouldReadUnverifiedIssuerForClientLookup() {
        KeyPair keyPair = rsaKeyPair();
        String assertion = assertion(keyPair, CLIENT_ID, CLIENT_ID, ISSUER, NOW - 30, NOW + 60);
        assertEquals(CLIENT_ID, validator.readIssuer(assertion));
    }

    @Test
    void shouldRejectWrongAudience() {
        KeyPair keyPair = rsaKeyPair();
        assertThrows(OAuthException.class, () -> validator.validate(
                assertion(keyPair, CLIENT_ID, CLIENT_ID, "https://evil.example", NOW - 30, NOW + 60),
                client(jwks(keyPair))));
    }

    @Test
    void shouldRejectSubjectMismatch() {
        KeyPair keyPair = rsaKeyPair();
        assertThrows(OAuthException.class, () -> validator.validate(
                assertion(keyPair, CLIENT_ID, "someone-else", ISSUER, NOW - 30, NOW + 60),
                client(jwks(keyPair))));
    }

    @Test
    void shouldRejectExpiredAssertion() {
        KeyPair keyPair = rsaKeyPair();
        assertThrows(OAuthException.class, () -> validator.validate(
                assertion(keyPair, CLIENT_ID, CLIENT_ID, ISSUER, NOW - 600, NOW - 60),
                client(jwks(keyPair))));
    }

    @Test
    void shouldRejectAssertionLifetimeExceedingWindow() {
        KeyPair keyPair = rsaKeyPair();
        assertThrows(OAuthException.class, () -> validator.validate(
                assertion(keyPair, CLIENT_ID, CLIENT_ID, ISSUER, NOW - 10_000, NOW + 60),
                client(jwks(keyPair))));
    }

    @Test
    void shouldRejectReplayedAssertion() {
        KeyPair keyPair = rsaKeyPair();
        String assertion = assertion(keyPair, CLIENT_ID, CLIENT_ID, ISSUER, NOW - 30, NOW + 60);
        validator.validate(assertion, client(jwks(keyPair)));
        OAuthException ex = assertThrows(OAuthException.class,
                () -> validator.validate(assertion, client(jwks(keyPair))));
        assertTrue(ex.getError().getErrorDescription().contains("already been used"));
    }

    @Test
    void shouldRejectHmacAssertionToPreventSecretConfusion() {
        KeyPair keyPair = rsaKeyPair();
        OAuthException ex = assertThrows(OAuthException.class,
                () -> validator.validate(hmacAssertion("server-side-secret-value"), client(jwks(keyPair))));
        assertTrue(ex.getError().getErrorDescription().contains("asymmetric"));
    }

    @Test
    void shouldRejectAssertionSignedWithUnknownKey() {
        KeyPair keyPair = rsaKeyPair();
        KeyPair otherPair = rsaKeyPair();
        String assertion = assertion(otherPair, CLIENT_ID, CLIENT_ID, ISSUER, NOW - 30, NOW + 60);
        assertThrows(OAuthException.class, () -> validator.validate(assertion, client(jwks(keyPair))));
    }

    private static String jwks(KeyPair keyPair) {
        JsonWebKey jwk = new JsonWebKey();
        jwk.setKeyType(KeyType.RSA);
        jwk.setKeyId("client-key-1");
        jwk.setPublicKeyUse(PublicKeyUse.SIGN);
        java.security.interfaces.RSAPublicKey rsa =
                (java.security.interfaces.RSAPublicKey) keyPair.getPublic();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        jwk.setProperty(JsonWebKey.RSA_MODULUS, encoder.encodeToString(rsa.getModulus().toByteArray()));
        jwk.setProperty(JsonWebKey.RSA_PUBLIC_EXP,
                encoder.encodeToString(rsa.getPublicExponent().toByteArray()));
        return JwkUtils.jwkSetToJson(new JsonWebKeys(List.of(jwk)));
    }
}
