package org.picketlink.auth.oauth.jwt;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JwtAccessTokenValidator {

    private final JwtSettings settings;
    private final Clock clock;

    public JwtAccessTokenValidator(JwtSettings settings) {
        this(settings, Clock.SYSTEM);
    }

    public JwtAccessTokenValidator(JwtSettings settings, Clock clock) {
        this.settings = settings;
        this.clock = clock;
    }

    public JwtClaims validate(String token) {
        if (token == null || token.isBlank()) {
            throw new JwtValidationException("Missing bearer token");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new JwtValidationException("Malformed JWT");
        }
        String expectedSignature = sign(parts[0] + "." + parts[1]);
        if (!MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                parts[2].getBytes(StandardCharsets.UTF_8))) {
            throw new JwtValidationException("Invalid JWT signature");
        }

        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String issuer = readStringClaim(payloadJson, "iss");
        if (!settings.getIssuer().equals(issuer)) {
            throw new JwtValidationException("Invalid JWT issuer");
        }
        long expiresAt = readNumberClaim(payloadJson, "exp");
        if (expiresAt <= clock.now().getEpochSecond()) {
            throw new JwtValidationException("JWT has expired");
        }
        String clientId = readStringClaim(payloadJson, "client_id");
        if (clientId == null || clientId.isBlank()) {
            clientId = readStringClaim(payloadJson, "sub");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new JwtValidationException("JWT missing client identity");
        }
        return new JwtClaims(clientId, readStringClaim(payloadJson, "scope"));
    }

    private String sign(String content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(settings.getSigningSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(content.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new IllegalStateException("Unable to verify JWT", ex);
        }
    }

    private static String readStringClaim(String payloadJson, String claim) {
        String marker = "\"" + claim + "\"";
        int index = payloadJson.indexOf(marker);
        if (index < 0) {
            return null;
        }
        int colon = payloadJson.indexOf(':', index + marker.length());
        int quoteStart = payloadJson.indexOf('"', colon + 1);
        if (quoteStart < 0) {
            return null;
        }
        int quoteEnd = payloadJson.indexOf('"', quoteStart + 1);
        if (quoteEnd < 0) {
            return null;
        }
        return payloadJson.substring(quoteStart + 1, quoteEnd);
    }

    private static long readNumberClaim(String payloadJson, String claim) {
        String marker = "\"" + claim + "\"";
        int index = payloadJson.indexOf(marker);
        if (index < 0) {
            return 0L;
        }
        int colon = payloadJson.indexOf(':', index + marker.length());
        if (colon < 0) {
            return 0L;
        }
        int end = colon + 1;
        while (end < payloadJson.length() && Character.isDigit(payloadJson.charAt(end))) {
            end++;
        }
        return Long.parseLong(payloadJson.substring(colon + 1, end).trim());
    }

    public interface Clock {
        Clock SYSTEM = new Clock() {
            public Instant now() {
                return Instant.now();
            }
        };

        Instant now();
    }
}
