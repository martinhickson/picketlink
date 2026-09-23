package org.picketlink.auth.oauth.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

class RsaJwtSignerTest {

    @Test
    void rs256TokenCarriesKidAudienceAndJti() {
        RsaJwtSigner signer = new RsaJwtSigner("key-1");
        JwtSettings settings = new JwtSettings("https://issuer.example", "unused", 3600L);
        JwtAccessTokenIssuer issuer = new JwtAccessTokenIssuer(settings, signer);
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        String token = issuer.issueToken("user1", "demo-client", Set.of("api.read"), Set.of("api"), issuedAt);

        String header = new String(java.util.Base64.getUrlDecoder().decode(token.split("\\.")[0]));
        String payload = new String(java.util.Base64.getUrlDecoder().decode(token.split("\\.")[1]));
        assertTrue(header.contains("\"alg\":\"RS256\""));
        assertTrue(header.contains("\"kid\":\"key-1\""));
        assertTrue(payload.contains("\"sub\":\"user1\""));
        assertTrue(payload.contains("\"aud\":[\"api\"]"));
        assertTrue(payload.contains("\"jti\""));
        assertTrue(signer.jwks().contains("\"kid\":\"key-1\""));

        JwtAccessTokenValidator validator = new JwtAccessTokenValidator(settings, () -> issuedAt, signer);
        assertEquals("demo-client", validator.validate(token).getClientId());
    }
}
