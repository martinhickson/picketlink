package org.picketlink.auth.oauth.issuance;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.token.AccessTokenRegistry;
import org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry;

/**
 * The five-line way to production-grade JWTs — everything the full stack offers (policy
 * engine, audit, rotation, revocation) with sane defaults, because JWT always costs more
 * time than it should:
 *
 * <pre>{@code
 * PicketLinkJwt jwt = PicketLinkJwt.issuer("https://auth.example")
 *         .ed25519()                       // or .rs256() / .es256() / .keyPair(pair, RS256)
 *         .audience("https://api.example") // audience pinning
 *         .build();
 *
 * String token = jwt.issue("user-42", Set.of("read"));   // subject + scopes
 * JwtClaims claims = jwt.validate(token);                // signature + time + revocation
 * }</pre>
 *
 * Defaults: 15-minute tokens, 1-hour cap, single-algorithm allow-list, 30s clock skew,
 * in-memory revocation registry, keys rotated with {@link #rotate()} (old keys keep
 * validating through the overlap window and stay published in {@link #jwks()}).
 */
public final class PicketLinkJwt {

    private final JwtIssuanceManager manager;
    private final Set<String> defaultAudiences;
    private final KeyFactory keyFactory;

    private PicketLinkJwt(JwtIssuanceManager manager, Set<String> defaultAudiences,
            KeyFactory keyFactory) {
        this.manager = manager;
        this.defaultAudiences = defaultAudiences;
        this.keyFactory = keyFactory;
    }

    public static IssuerStep issuer(String issuer) {
        return new IssuerStep(issuer);
    }

    /** Key generation spec so {@link #rotate()} matches the original algorithm family. */
    private interface KeyFactory {

        SigningKey newKey(String keyId) throws Exception;
    }

    /** Step 1: the issuer identifier embedded in every token. */
    public static final class IssuerStep {

        private final String issuer;

        private IssuerStep(String issuer) {
            this.issuer = issuer;
        }

        public BuildStep rs256() {
            return generated("RSA", 2048, SignatureAlgorithm.RS256);
        }

        public BuildStep es256() {
            BuildStep step = new BuildStep(issuer, new KeyFactory() {
                @Override
                public SigningKey newKey(String keyId) throws Exception {
                    return SigningKey.forKeyPair(keyId, ecKeyPair(), SignatureAlgorithm.ES256);
                }
            });
            return step.initial(SigningKey.forKeyPair("key-1", ecKeyPair(), SignatureAlgorithm.ES256));
        }

        /** Ed25519 — compact, fast, native on JVM 15+. */
        public BuildStep ed25519() {
            BuildStep step = new BuildStep(issuer, new KeyFactory() {
                @Override
                public SigningKey newKey(String keyId) throws Exception {
                    return SigningKey.ed25519KeyPair(keyId, keyPair("Ed25519", 0));
                }
            });
            return step.initial(SigningKey.ed25519KeyPair("key-1", keyPair("Ed25519", 0)));
        }

        public BuildStep keyPair(KeyPair keyPair, SignatureAlgorithm algorithm) {
            return new BuildStep(issuer, null).initial(SigningKey.forKeyPair("key-1", keyPair, algorithm));
        }

        private BuildStep generated(final String algorithm, final int keySize,
                final SignatureAlgorithm signatureAlgorithm) {
            return new BuildStep(issuer, new KeyFactory() {
                @Override
                public SigningKey newKey(String keyId) throws Exception {
                    return SigningKey.forKeyPair(keyId, keyPair(algorithm, keySize), signatureAlgorithm);
                }
            }).initial(SigningKey.forKeyPair("key-1", keyPair(algorithm, keySize), signatureAlgorithm));
        }

        private static KeyPair ecKeyPair() {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"),
                        new SecureRandom());
                return generator.generateKeyPair();
            } catch (java.security.GeneralSecurityException ex) {
                throw new IllegalStateException("EC P-256 unavailable", ex);
            }
        }

        private static KeyPair keyPair(String algorithm, int keySize) {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
                if (keySize > 0) {
                    generator.initialize(keySize, new SecureRandom());
                }
                return generator.generateKeyPair();
            } catch (java.security.NoSuchAlgorithmException ex) {
                throw new IllegalStateException("algorithm unavailable: " + algorithm, ex);
            }
        }
    }

    /** Step 2 (optional): policy defaults and build. */
    public static class BuildStep {

        private final String issuer;
        private final KeyFactory keyFactory;
        private SigningKey initialKey;
        private long lifetimeSeconds = 900L;
        private long maxLifetimeSeconds = 3600L;
        private final Set<String> audiences = new LinkedHashSet<>();
        private AccessTokenRegistry tokenRegistry = new InMemoryAccessTokenRegistry();
        private IssuanceAuditListener auditListener;

        BuildStep(String issuer, KeyFactory keyFactory) {
            this.issuer = issuer;
            this.keyFactory = keyFactory;
        }

        BuildStep initial(SigningKey key) {
            this.initialKey = key;
            return this;
        }

        public BuildStep lifetimeSeconds(long lifetimeSeconds) {
            this.lifetimeSeconds = lifetimeSeconds;
            return this;
        }

        public BuildStep maxLifetimeSeconds(long maxLifetimeSeconds) {
            this.maxLifetimeSeconds = maxLifetimeSeconds;
            return this;
        }

        public BuildStep audience(String audience) {
            audiences.add(audience);
            return this;
        }

        public BuildStep tokenRegistry(AccessTokenRegistry registry) {
            this.tokenRegistry = registry;
            return this;
        }

        public BuildStep audit(IssuanceAuditListener listener) {
            this.auditListener = listener;
            return this;
        }

        public PicketLinkJwt build() {
            CxfJoseJwtSigningService signingService =
                    new CxfJoseJwtSigningService(issuer, List.of(initialKey), initialKey.getKeyId());
            IssuancePolicyEngine policy = new IssuancePolicyEngine(List.of(
                    new SecureSigningAlgorithmRule(Set.of(algorithmName(initialKey))),
                    new MaxTokenLifetimeRule(maxLifetimeSeconds)));
            return new PicketLinkJwt(new JwtIssuanceManager(issuer, signingService, policy,
                    tokenRegistry, auditListener, algorithmName(initialKey), lifetimeSeconds),
                    audiences, keyFactory);
        }

        private static String algorithmName(SigningKey key) {
            return key.isEd25519() ? "EdDSA" : key.getAlgorithm().name();
        }
    }

    /** Issues a token for a subject with the given scopes. */
    public String issue(String subject, Set<String> scopes) {
        RegisteredClient client = RegisteredClient.builder(subject == null ? "jwt" : subject, null)
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.PRIVATE_KEY_JWT)
                .jwks("{\"keys\":[]}")
                .build();
        return manager.issue(IssuanceRequest.forClient(client)
                .grantType("jwt")
                .scopes(scopes)
                .subject(subject)
                .audiences(defaultAudiences)
                .build()).getTokenValue();
    }

    /**
     * Validates a token: signature, issuer, expiry/not-before (30s clock skew) and
     * revocation — everything through the issuance chokepoint.
     */
    public JwtClaims validate(String token) {
        return manager.validate(token);
    }

    /** Resource-server validation with explicit requirements (audience, scope). */
    public JwtClaims validate(String token, JwtRequirements requirements) {
        JwtClaims claims = manager.validate(token);
        requirements.check(claims);
        return claims;
    }

    /** Revokes a previously issued token. */
    public boolean revoke(String token) {
        return manager.revoke(token);
    }

    /** The JWKS document for resource servers (RSA/EC/OKP-Ed25519 keys). */
    public String jwks() {
        return manager.getSigningService().publicJwksJson();
    }

    /**
     * Generates a new key of the same algorithm family and makes it active; tokens signed
     * with the previous key keep validating (overlap window) and stay in {@link #jwks()}.
     *
     * @return the new key id
     */
    public String rotate() throws Exception {
        CxfJoseJwtSigningService service = (CxfJoseJwtSigningService) manager.getSigningService();
        if (keyFactory == null) {
            throw new IllegalStateException("rotation requires a generated key (rs256/es256/ed25519)");
        }
        SigningKey fresh = keyFactory.newKey("key-" + UUID.randomUUID());
        service.addKey(fresh);
        service.setActiveKeyId(fresh.getKeyId());
        return fresh.getKeyId();
    }
}
