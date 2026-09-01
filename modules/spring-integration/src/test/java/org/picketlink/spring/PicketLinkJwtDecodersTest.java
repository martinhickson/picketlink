package org.picketlink.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.util.List;
import java.util.Set;

import com.sun.net.httpserver.HttpServer;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.issuance.CxfJoseJwtSigningService;
import org.picketlink.auth.oauth.issuance.SigningKey;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Cross-stack verification: JWTs issued by the PicketLink issuance layer are validated by a
 * plain Spring Security resource-server decoder through the issuer's JWKS — the integration
 * promise of the adapter.
 */
class PicketLinkJwtDecodersTest {

    private static final String ISSUER = "https://auth.example.test";

    private CxfJoseJwtSigningService signingService;
    private HttpServer jwksServer;
    private String jwksUri;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        signingService = new CxfJoseJwtSigningService(ISSUER,
                List.of(SigningKey.forKeyPair("test-key-1", keyPair, SignatureAlgorithm.RS256)),
                "test-key-1", Clock.systemUTC());

        String jwks = signingService.publicJwksJson();
        jwksServer = HttpServer.create(new InetSocketAddress(0), 0);
        jwksServer.createContext("/.well-known/jwks.json", exchange -> {
            byte[] body = jwks.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        jwksServer.start();
        jwksUri = "http://localhost:" + jwksServer.getAddress().getPort()
                + "/.well-known/jwks.json";
    }

    @AfterEach
    void tearDown() {
        if (jwksServer != null) {
            jwksServer.stop(0);
        }
    }

    private String issueToken(String subject, Set<String> scopes) {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setSubject(subject);
        claims.setClaim("client_id", subject);
        if (!scopes.isEmpty()) {
            claims.setClaim("scope", String.join(" ", scopes));
        }
        claims.setIssuedAt(java.time.Instant.now().getEpochSecond());
        claims.setExpiryTime(java.time.Instant.now().getEpochSecond() + 300);
        claims.setTokenId("token-" + System.nanoTime());
        return signingService.sign(claims, "RS256");
    }

    @Test
    void shouldDecodePicketLinkTokenViaJwksUri() {
        JwtDecoder decoder = PicketLinkJwtDecoders.fromJwksUri(jwksUri, ISSUER);
        Jwt jwt = decoder.decode(issueToken("rest-client", Set.of("read", "write")));

        assertEquals(ISSUER, jwt.getClaimAsString("iss"));
        assertEquals("rest-client", jwt.getSubject());
        String scope = String.valueOf(jwt.getClaims().get("scope"));
        assertTrue(scope.contains("read") && scope.contains("write"));
    }

    @Test
    void shouldDecodeWithStaticJwks() {
        JwtDecoder decoder = PicketLinkJwtDecoders.fromStaticJwks(
                PicketLinkJwtDecoders.fetchJwks(jwksUri), ISSUER);
        assertNotNull(decoder.decode(issueToken("rest-client", Set.of("read"))));
    }

    @Test
    void shouldRejectForeignIssuer() {
        JwtDecoder decoder = PicketLinkJwtDecoders.fromJwksUri(jwksUri, "https://other-issuer.example");
        assertThrows(JwtException.class,
                () -> decoder.decode(issueToken("rest-client", Set.of("read"))));
    }

    @Test
    void shouldRejectTamperedToken() {
        JwtDecoder decoder = PicketLinkJwtDecoders.fromJwksUri(jwksUri, ISSUER);
        String token = issueToken("rest-client", Set.of("read"));
        // swap the payload for attacker-controlled claims, keeping the signature
        String[] parts = token.split("\\.");
        String forgedPayload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"iss\":\"https://auth.example.test\",\"sub\":\"admin\",\"exp\":9999999999}"
                        .getBytes(StandardCharsets.UTF_8));
        assertThrows(JwtException.class, () -> decoder.decode(parts[0] + "." + forgedPayload + "." + parts[2]));
    }

    @Test
    void shouldRejectExpiredToken() {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setSubject("rest-client");
        claims.setIssuedAt(java.time.Instant.now().getEpochSecond() - 1000);
        claims.setExpiryTime(java.time.Instant.now().getEpochSecond() - 500);
        String token = signingService.sign(claims, "RS256");

        JwtDecoder decoder = PicketLinkJwtDecoders.fromJwksUri(jwksUri, ISSUER);
        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void converterShouldMapScopesToAuthorities() {
        JwtDecoder decoder = PicketLinkJwtDecoders.fromJwksUri(jwksUri, ISSUER);
        Jwt jwt = decoder.decode(issueToken("rest-client", Set.of("read", "write")));

        PicketLinkJwtAuthenticationConverter converter = new PicketLinkJwtAuthenticationConverter();
        JwtAuthenticationToken authentication = converter.convert(jwt);

        assertEquals("rest-client", authentication.getName());
        List<String> authorities = PicketLinkJwtAuthenticationConverter.authorityNames(authentication);
        assertTrue(authorities.contains("SCOPE_read"));
        assertTrue(authorities.contains("SCOPE_write"));
    }

    @Test
    void fetchJwksShouldReturnThePublishedDocument() {
        String jwks = PicketLinkJwtDecoders.fetchJwks(jwksUri);
        assertTrue(jwks.contains("test-key-1"));
        assertTrue(jwks.contains("\"kty\":\"RSA\""));
    }
}
