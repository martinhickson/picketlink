package org.picketlink.auth.oauth.issuance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.jwt.JwtValidationException;

/**
 * Resource-server validation requirements, in the style Spring Security taught everyone:
 *
 * <pre>{@code
 * JwtRequirements.requiredAudience("https://api.example").requireScope("read").build();
 * }</pre>
 *
 * Applied after the cryptographic checks in {@link PicketLinkJwt#validate(String, JwtRequirements)}.
 */
public final class JwtRequirements {

    private final List<String> requiredAudiences = new ArrayList<>();
    private final List<String> requiredScopes = new ArrayList<>();
    private String requiredSubject;

    private JwtRequirements() {
    }

    public static JwtRequirements requireAudience(String... audiences) {
        JwtRequirements requirements = new JwtRequirements();
        requirements.requiredAudiences.addAll(Arrays.asList(audiences));
        return requirements;
    }

    public static JwtRequirements requireScope(String... scopes) {
        JwtRequirements requirements = new JwtRequirements();
        requirements.requiredScopes.addAll(Arrays.asList(scopes));
        return requirements;
    }

    public static JwtRequirements requireSubject(String subject) {
        JwtRequirements requirements = new JwtRequirements();
        requirements.requiredSubject = subject;
        return requirements;
    }

    public JwtRequirements audience(String... audiences) {
        requiredAudiences.addAll(Arrays.asList(audiences));
        return this;
    }

    public JwtRequirements scope(String... scopes) {
        requiredScopes.addAll(Arrays.asList(scopes));
        return this;
    }

    public JwtRequirements subject(String subject) {
        this.requiredSubject = subject;
        return this;
    }

    void check(JwtClaims claims) {
        if (requiredSubject != null && !requiredSubject.equals(claims.getSubject())) {
            throw new JwtValidationException("Token subject mismatch");
        }
        for (String audience : requiredAudiences) {
            List<String> audiences = claims.getAudiences();
            boolean matched = audiences != null && audiences.contains(audience);
            if (!matched && audience.equals(claims.getAudience())) {
                matched = true;
            }
            if (!matched) {
                throw new JwtValidationException("Token audience does not include " + audience);
            }
        }
        if (!requiredScopes.isEmpty()) {
            Object scope = claims.getClaim(JwtIssuanceManager.CLAIM_SCOPE);
            List<String> granted = scope == null
                    ? java.util.Collections.emptyList()
                    : Arrays.asList(scope.toString().trim().split("\\s+"));
            for (String required : requiredScopes) {
                if (!granted.contains(required)) {
                    throw new JwtValidationException("Token does not grant scope " + required);
                }
            }
        }
    }
}
