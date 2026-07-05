package org.picketlink.auth.oauth.jwt;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;

public class JwtAccessTokenIssuer {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final JwtSettings settings;

    public JwtAccessTokenIssuer(JwtSettings settings) {
        this.settings = settings;
    }

    public String issueToken(String clientId, Set<String> scopes, Instant issuedAt) {
        Instant expiresAt = issuedAt.plusSeconds(settings.getAccessTokenLifetimeSeconds());
        String header = encodeJson("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = encodeJson(buildPayload(clientId, scopes, issuedAt, expiresAt));
        String signature = sign(header + "." + payload);
        return header + "." + payload + "." + signature;
    }

    private String buildPayload(String clientId, Set<String> scopes, Instant issuedAt, Instant expiresAt) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendClaim(json, "iss", settings.getIssuer(), true);
        appendClaim(json, "sub", clientId, false);
        appendClaim(json, "client_id", clientId, false);
        if (scopes != null && !scopes.isEmpty()) {
            appendClaim(json, "scope", String.join(" ", scopes), false);
        }
        appendNumberClaim(json, "iat", issuedAt.getEpochSecond(), false);
        appendNumberClaim(json, "exp", expiresAt.getEpochSecond(), false);
        json.append('}');
        return json.toString();
    }

    private static void appendClaim(StringBuilder json, String name, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":\"")
                .append(OAuthJsonWriter.escape(value)).append('"');
    }

    private static void appendNumberClaim(StringBuilder json, String name, long value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(OAuthJsonWriter.escape(name)).append("\":").append(value);
    }

    private static String encodeJson(String json) {
        return URL_ENCODER.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private String sign(String content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(settings.getSigningSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return URL_ENCODER.encodeToString(mac.doFinal(content.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new IllegalStateException("Unable to sign JWT", ex);
        }
    }
}
