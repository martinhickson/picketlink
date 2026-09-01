package org.picketlink.auth.oauth.admin;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.store.ClientRegistrationStore;
import org.picketlink.auth.oauth.client.store.PersistingClientRegistry;
import org.picketlink.auth.oauth.issuance.CxfJoseJwtSigningService;
import org.picketlink.auth.oauth.issuance.JwtIssuanceManager;
import org.picketlink.auth.oauth.issuance.LoggingIssuanceAuditListener;
import org.picketlink.auth.oauth.issuance.SigningKey;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;
import org.picketlink.auth.oauth.service.JwtClientCredentialsTokenService;
import org.picketlink.auth.oauth.store.IssuancePolicyConfig;
import org.picketlink.auth.oauth.store.IssuancePolicyStore;
import org.picketlink.auth.oauth.store.JdbcAccessTokenRegistry;
import org.picketlink.auth.oauth.store.JdbcClientRegistrationStore;
import org.picketlink.auth.oauth.store.JdbcClobDocumentStore;
import org.picketlink.auth.oauth.store.JdbcConnectionSource;
import org.picketlink.auth.oauth.store.SigningKeyStore;
import org.picketlink.auth.oauth.token.AccessTokenRegistry;
import org.picketlink.auth.oauth.token.InMemoryAccessTokenRegistry;
import org.jboss.logging.Logger;

/**
 * Assembles the managed JWT issuance stack from the configured stores:
 * clients/policies/keys as JSON documents (CLOB when JDBC is configured), the token registry,
 * the {@link JwtIssuanceManager} and the admin API resources guarded by
 * {@link AdminScopeFilter}. Seeds the bootstrap {@code auth-admin} client on first start.
 *
 * <p>Store selection: {@code -Dpicketlink.auth.store=jdbc} with
 * {@code picketlink.auth.jdbc.url|user|password} (plus optional {@code driver}); otherwise
 * in-memory/ephemeral equivalents are used.
 */
public final class ManagedIssuanceServer {

    public static final String ADMIN_CLIENT_ID = "auth-admin";
    public static final String STORE_PROPERTY = "picketlink.auth.store";
    public static final String JDBC_URL_PROPERTY = "picketlink.auth.jdbc.url";
    public static final String JDBC_USER_PROPERTY = "picketlink.auth.jdbc.user";
    public static final String JDBC_PASSWORD_PROPERTY = "picketlink.auth.jdbc.password";
    public static final String ADMIN_CLIENT_SECRET_ENV = "PICKETLINK_ADMIN_CLIENT_SECRET";

    private static final Logger LOG = Logger.getLogger(ManagedIssuanceServer.class);

    private final String issuer;
    private final ClientRegistrationStore clientStore;
    private final AccessTokenRegistry tokenRegistry;
    private final IssuancePolicyStore policyStore;
    private final SigningKeyStore keyStore;
    private final JwtIssuanceManager issuanceManager;
    private final JwtClientCredentialsTokenService tokenService;
    private final List<Object> adminResources;

    private ManagedIssuanceServer(Builder builder) throws Exception {
        this.issuer = builder.issuer;
        JdbcConnectionSource connectionSource = builder.connectionSource;
        boolean jdbc = connectionSource != null;

        if (jdbc) {
            JdbcClobDocumentStore documentStore = new JdbcClobDocumentStore(connectionSource);
            this.clientStore = builder.clientStore != null
                    ? builder.clientStore
                    : new JdbcClientRegistrationStore(documentStore);
            this.tokenRegistry = new JdbcAccessTokenRegistry(connectionSource);
            this.policyStore = builder.policyStore != null
                    ? builder.policyStore
                    : new org.picketlink.auth.oauth.store.JdbcIssuancePolicyStore(documentStore);
            this.keyStore = builder.keyStore != null ? builder.keyStore : new SigningKeyStore(documentStore);
        } else {
            this.clientStore = builder.clientStore != null
                    ? builder.clientStore
                    : new org.picketlink.auth.oauth.client.store.InMemoryClientRegistrationStore();
            this.tokenRegistry = new InMemoryAccessTokenRegistry();
            this.policyStore = builder.policyStore != null
                    ? builder.policyStore
                    : new IssuancePolicyStore.StaticIssuancePolicyStore();
            this.keyStore = null;
        }

        IssuancePolicyConfig policy = policyStore.load();
        CxfJoseJwtSigningService signingService;
        if (keyStore != null) {
            if (keyStore.loadDocument().getKeys().isEmpty()) {
                // first start: generate the initial signing key into the keystore
                keyStore.rotate();
            }
            signingService = keyStore.toSigningService(issuer);
        } else {
            signingService = ephemeralSigningService(issuer);
        }

        this.issuanceManager = JwtIssuanceManager.withDefaultPolicy(issuer, signingService,
                tokenRegistry, new LoggingIssuanceAuditListener(),
                policy.getDefaultAlgorithm(), policy.getDefaultLifetimeSeconds(),
                policy.getMaxLifetimeSeconds());

        ClientCredentialsAuthenticator authenticator = new ClientCredentialsAuthenticator(
                new PersistingClientRegistry(clientStore), new ConstantTimeClientSecretMatcher());
        this.tokenService = new JwtClientCredentialsTokenService(authenticator, issuanceManager);

        seedAdminClient();

        this.adminResources = new ArrayList<>();
        adminResources.add(new AdminClientResource(clientStore));
        adminResources.add(new AdminPolicyResource(policyStore));
        if (keyStore != null) {
            adminResources.add(new AdminKeyResource(keyStore));
        }
        if (tokenRegistry instanceof JdbcAccessTokenRegistry) {
            adminResources.add(new AdminTokenResource((JdbcAccessTokenRegistry) tokenRegistry));
        }
    }

    private static CxfJoseJwtSigningService ephemeralSigningService(String issuer) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048, new SecureRandom());
            return new CxfJoseJwtSigningService(issuer,
                    List.of(SigningKey.forKeyPair("ephemeral-1",
                            generator.generateKeyPair(), SignatureAlgorithm.RS256)),
                    "ephemeral-1");
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to generate ephemeral signing key", ex);
        }
    }

    private void seedAdminClient() {
        if (clientStore.findByClientId(ADMIN_CLIENT_ID).isPresent()) {
            return;
        }
        String secret = System.getenv(ADMIN_CLIENT_SECRET_ENV);
        boolean generated = secret == null || secret.isBlank();
        if (generated) {
            secret = new org.picketlink.auth.oauth.token.AccessTokenGenerator(32).generate();
        }
        Set<String> scopes = new LinkedHashSet<>();
        scopes.add(AdminScopeFilter.ADMIN_SCOPE);
        clientStore.save(RegisteredClient.builder(ADMIN_CLIENT_ID, secret)
                .scopes(scopes)
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build());
        if (generated) {
            LOG.warnf("Seeded admin client '%s' with generated secret '%s' — set %s to control it",
                    ADMIN_CLIENT_ID, secret, ADMIN_CLIENT_SECRET_ENV);
        }
    }

    public String getIssuer() {
        return issuer;
    }

    public JwtIssuanceManager getIssuanceManager() {
        return issuanceManager;
    }

    public JwtClientCredentialsTokenService getTokenService() {
        return tokenService;
    }

    public ClientRegistrationStore getClientStore() {
        return clientStore;
    }

    public AccessTokenRegistry getTokenRegistry() {
        return tokenRegistry;
    }

    /** The signing key store; null unless the JDBC profile is active. */
    public SigningKeyStore getKeyStore() {
        return keyStore;
    }

    public boolean isJdbcProfile() {
        return tokenRegistry instanceof JdbcAccessTokenRegistry;
    }

    public IssuancePolicyStore getPolicyStore() {
        return policyStore;
    }

    /** Admin API JAX-RS resources; register together with {@link AdminScopeFilter}. */
    public List<Object> getAdminResources() {
        return adminResources;
    }

    /** Reads the JDBC connection properties from system properties. */
    public static JdbcConnectionSource connectionSourceFromProperties() {
        if (!"jdbc".equalsIgnoreCase(System.getProperty(STORE_PROPERTY))) {
            return null;
        }
        String url = System.getProperty(JDBC_URL_PROPERTY);
        if (url == null || url.isBlank()) {
            throw new IllegalStateException(STORE_PROPERTY + "=jdbc requires " + JDBC_URL_PROPERTY);
        }
        return new org.picketlink.auth.oauth.store.DriverManagerConnectionSource(
                url,
                System.getProperty(JDBC_USER_PROPERTY),
                System.getProperty(JDBC_PASSWORD_PROPERTY));
    }

    /** Issuer from {@code picketlink.auth.issuer} or {@code PICKETLINK_AUTH_ISSUER}; may be null. */
    public static String issuerFromEnvironment() {
        String issuer = System.getProperty("picketlink.auth.issuer",
                System.getenv("PICKETLINK_AUTH_ISSUER"));
        return issuer == null || issuer.isBlank() ? null : issuer;
    }

    public static Builder builder(String issuer) {
        return new Builder(issuer);
    }

    public static final class Builder {

        private final String issuer;
        private ClientRegistrationStore clientStore;
        private IssuancePolicyStore policyStore;
        private SigningKeyStore keyStore;
        private JdbcConnectionSource connectionSource;

        private Builder(String issuer) {
            this.issuer = issuer;
        }

        public Builder clientStore(ClientRegistrationStore clientStore) {
            this.clientStore = clientStore;
            return this;
        }

        public Builder policyStore(IssuancePolicyStore policyStore) {
            this.policyStore = policyStore;
            return this;
        }

        public Builder keyStore(SigningKeyStore keyStore) {
            this.keyStore = keyStore;
            return this;
        }

        public Builder connectionSource(JdbcConnectionSource connectionSource) {
            this.connectionSource = connectionSource;
            return this;
        }

        public ManagedIssuanceServer build() throws Exception {
            return new ManagedIssuanceServer(this);
        }
    }
}
