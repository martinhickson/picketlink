package org.picketlink.auth.oauth.jwt;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;

public class JwtAccessTokenIssuer {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final JwtSettings settings;
    private final JwtSigner signer;

    public JwtAccessTokenIssuer(JwtSettings settings) {
        this(settings, null);
    }

    public JwtAccessTokenIssuer(JwtSettings settings, JwtSigner signer) {
        this.settings = settings;
        this.signer = signer;
    }

    public String issueToken(String clientId, Set<String> scopes, Instant issuedAt) {
        return issueToken(clientId, clientId, scopes, Set.of(), issuedAt);
    }

    public String issueToken(String subject, String clientId, Set<String> scopes, Set<String> audiences,
            Instant issuedAt) {
        Instant expiresAt = issuedAt.plusSeconds(settings.getAccessTokenLifetimeSeconds());
        String header = encodeJson(headerJson());
        String payload = encodeJson(buildPayload(subject, clientId, scopes, audiences, issuedAt, expiresAt));
        String signature = sign(header + "." + payload);
        return header + "." + payload + "." + signature;
    }

    public JwtSigner getSigner() {
        return signer;
    }

    private String headerJson() {
        String algorithm = signer == null ? "HS256" : signer.algorithm();
        StringBuilder json = new StringBuilder();
        json.append("{\"alg\":\"").append(algorithm).append("\",\"typ\":\"JWT\"");
        if (signer != null && signer.keyId() != null) {
            json.append(",\"kid\":\"").append(OAuthJsonWriter.escape(signer.keyId())).append('"');
        }
        json.append('}');
        return json.toString();
    }

    private String buildPayload(String subject, String clientId, Set<String> scopes, Set<String> audiences,
            Instant issuedAt, Instant expiresAt) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendClaim(json, "iss", settings.getIssuer(), true);
        appendClaim(json, "sub", subject, false);
        appendClaim(json, "client_id", clientId, false);
        appendClaim(json, "jti", UUID.randomUUID().toString(), false);
        if (audiences != null && !audiences.isEmpty()) {
            json.append(",\"aud\":[");
            boolean firstAudience = true;
            for (String audience : audiences) {
                if (!firstAudience) {
                    json.append(',');
                }
                firstAudience = false;
                json.append('"').append(OAuthJsonWriter.escape(audience)).append('"');
            }
            json.append(']');
        }
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
        if (signer != null) {
            return URL_ENCODER.encodeToString(signer.sign(content.getBytes(StandardCharsets.UTF_8)));
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(settings.getSigningSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return URL_ENCODER.encodeToString(mac.doFinal(content.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new IllegalStateException("Unable to sign JWT", ex);
        }
    }
}
