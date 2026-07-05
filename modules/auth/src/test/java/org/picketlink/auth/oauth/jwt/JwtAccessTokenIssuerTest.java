package org.picketlink.auth.oauth.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class JwtAccessTokenIssuerTest {

    @Test
    void issuesThreePartJwt() {
        JwtSettings settings = new JwtSettings("http://localhost/auth", "test-secret", 3600L);
        JwtAccessTokenIssuer issuer = new JwtAccessTokenIssuer(settings);
        String token = issuer.issueToken("demo-client", Collections.singleton("api.read"), Instant.EPOCH);
        assertEquals(3, token.split("\\.").length);
    }

    @Test
    void validatorAcceptsIssuedToken() {
        JwtSettings settings = new JwtSettings("http://localhost/auth", "test-secret", 3600L);
        JwtAccessTokenIssuer issuer = new JwtAccessTokenIssuer(settings);
        final Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        String token = issuer.issueToken("demo-client", Collections.singleton("api.read"), issuedAt);
        JwtAccessTokenValidator validator = new JwtAccessTokenValidator(settings, new JwtAccessTokenValidator.Clock() {
            public Instant now() {
                return issuedAt;
            }
        });
        JwtClaims claims = validator.validate(token);
        assertEquals("demo-client", claims.getClientId());
        assertEquals("api.read", claims.getScope());
    }

    @Test
    void validatorRejectsTamperedToken() {
        JwtSettings settings = new JwtSettings("http://localhost/auth", "test-secret", 3600L);
        JwtAccessTokenIssuer issuer = new JwtAccessTokenIssuer(settings);
        final Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        String token = issuer.issueToken("demo-client", Collections.singleton("api.read"), issuedAt);
        JwtAccessTokenValidator validator = new JwtAccessTokenValidator(settings, new JwtAccessTokenValidator.Clock() {
            public Instant now() {
                return issuedAt;
            }
        });
        assertThrows(JwtValidationException.class, new org.junit.jupiter.api.function.Executable() {
            public void execute() {
                validator.validate(token + "x");
            }
        });
    }
}
