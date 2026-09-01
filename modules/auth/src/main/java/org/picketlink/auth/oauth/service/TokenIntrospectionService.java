package org.picketlink.auth.oauth.service;

import java.util.List;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.issuance.JwtIssuanceManager;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;
import org.picketlink.auth.oauth.model.TokenRequest;

/**
 * RFC 7662 token introspection. Unknown, invalid, expired or revoked tokens yield
 * {@code {"active":false}} rather than an error, per the RFC.
 */
public class TokenIntrospectionService {

    private final ClientCredentialsAuthenticator authenticator;
    private final JwtIssuanceManager issuanceManager;

    public TokenIntrospectionService(ClientCredentialsAuthenticator authenticator,
            JwtIssuanceManager issuanceManager) {
        this.authenticator = authenticator;
        this.issuanceManager = issuanceManager;
    }

    public String introspect(TokenRequest request) {
        authenticator.authenticate(request);
        String token = request.getFormParameter(OAuthConstants.ACCESS_TOKEN);
        String json;
        if (token == null || token.isBlank()) {
            json = inactive();
        } else {
            try {
                JwtClaims claims = issuanceManager.validate(token);
                json = activeResponse(claims);
            } catch (RuntimeException ex) {
                json = inactive();
            }
        }
        return json;
    }

    private static String activeResponse(JwtClaims claims) {
        JsonBuilder json = new JsonBuilder();
        json.bool(OAuthConstants.ACTIVE, true);
        json.field("scope", stringClaim(claims, JwtIssuanceManager.CLAIM_SCOPE));
        json.field(OAuthConstants.CLIENT_ID, stringClaim(claims, JwtIssuanceManager.CLAIM_CLIENT_ID));
        json.field(OAuthConstants.SUB, claims.getSubject());
        json.field(OAuthConstants.ISS, claims.getIssuer());
        json.field(OAuthConstants.JTI, claims.getTokenId());
        List<String> audiences = claims.getAudiences();
        if (audiences != null && !audiences.isEmpty()) {
            json.field(OAuthConstants.AUD, String.join(" ", audiences));
        }
        json.number(OAuthConstants.EXP, claims.getExpiryTime());
        json.number(OAuthConstants.IAT, claims.getIssuedAt());
        return json.toString();
    }

    private static String inactive() {
        return "{\"" + OAuthConstants.ACTIVE + "\":false}";
    }

    private static String stringClaim(JwtClaims claims, String name) {
        Object value = claims.getClaim(name);
        return value != null ? value.toString() : null;
    }

    /** Minimal JSON object writer that skips null values and handles comma placement. */
    private static final class JsonBuilder {

        private final StringBuilder json = new StringBuilder();
        private boolean empty = true;

        JsonBuilder() {
            json.append('{');
        }

        void field(String name, String value) {
            if (value == null) {
                return;
            }
            separator();
            json.append('"').append(OAuthJsonWriter.escape(name)).append("\":\"")
                    .append(OAuthJsonWriter.escape(value)).append('"');
        }

        void bool(String name, boolean value) {
            separator();
            json.append('"').append(OAuthJsonWriter.escape(name)).append("\":").append(value);
        }

        void number(String name, Long value) {
            if (value == null) {
                return;
            }
            separator();
            json.append('"').append(OAuthJsonWriter.escape(name)).append("\":").append(value);
        }

        private void separator() {
            if (!empty) {
                json.append(',');
            }
            empty = false;
        }

        @Override
        public String toString() {
            return json.append('}').toString();
        }
    }
}
