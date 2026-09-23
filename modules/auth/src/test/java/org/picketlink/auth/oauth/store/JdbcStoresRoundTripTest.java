package org.picketlink.auth.oauth.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.picketlink.auth.oauth.client.store.ClientRegistrationJsonCodec;
import org.picketlink.auth.oauth.model.AccessTokenRecord;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenEndpointAuthMethod;

/** Store round-trips on SQLite — the repository's default embedded test database (H2 banned). */
class JdbcStoresRoundTripTest {

    @TempDir
    Path tempDir;

    private JdbcClobDocumentStore documentStore;

    @BeforeEach
    void setUp() {
        documentStore = new JdbcClobDocumentStore(new DriverManagerConnectionSource(
                "jdbc:sqlite:" + tempDir.resolve("stores.db"), null, null));
        documentStore.save("clients", ClientRegistrationJsonCodec.write(List.of()), 0L);
    }

    @Test
    void clientStoreShouldRoundTripAllRegistrationFields() throws Exception {
        JdbcClientRegistrationStore store = new JdbcClientRegistrationStore(documentStore);

        String jwks = jwksJson();
        RegisteredClient jwksClient = RegisteredClient.builder("automated-client", null)
                .tokenEndpointAuthMethod(TokenEndpointAuthMethod.PRIVATE_KEY_JWT)
                .scope("read")
                .allowedAudiences(Set.of("https://api.example.test"))
                .jwks(jwks)
                .maxTokenLifetimeSeconds(120L)
                .build();
        RegisteredClient secretClient = RegisteredClient.builder("secret-client", "s3cret")
                .scope("write")
                .build();
        store.save(jwksClient);
        store.save(secretClient);

        Optional<RegisteredClient> loaded = store.findByClientId("automated-client");
        assertTrue(loaded.isPresent());
        RegisteredClient client = loaded.get();
        assertEquals(TokenEndpointAuthMethod.PRIVATE_KEY_JWT, client.getTokenEndpointAuthMethod());
        assertEquals(Set.of("read"), client.getScopes());
        assertEquals(Set.of("https://api.example.test"), client.getAllowedAudiences());
        assertEquals(jwks, client.getJwks());
        assertEquals(120L, client.getMaxTokenLifetimeSeconds());
        assertEquals("s3cret", store.findByClientId("secret-client").get().getClientSecret());

        assertTrue(store.delete("secret-client"));
        assertFalse(store.delete("secret-client"));
        assertEquals(1, store.findAll().size());
    }

    @Test
    void tokenRegistryShouldPersistHashedTokensAcrossRestart() {
        DriverManagerConnectionSource source = new DriverManagerConnectionSource(
                "jdbc:sqlite:" + tempDir.resolve("tokens.db"), null, null);
        JdbcAccessTokenRegistry registry = new JdbcAccessTokenRegistry(source);
        Set<String> scopes = new LinkedHashSet<>();
        scopes.add("read");
        registry.store(new AccessTokenRecord("jwt-value-1", "rest-client", scopes,
                Instant.now(), Instant.now().plusSeconds(300)));

        assertTrue(registry.findByTokenValue("jwt-value-1").isPresent());
        assertEquals("rest-client", registry.findByTokenValue("jwt-value-1").get().getClientId());
        assertFalse(registry.findByTokenValue("jwt-value-2").isPresent());

        // restart: same database file, new registry instance
        JdbcAccessTokenRegistry reopened = new JdbcAccessTokenRegistry(source);
        assertTrue(reopened.findByTokenValue("jwt-value-1").isPresent());

        List<JdbcAccessTokenRegistry.TokenRecordView> records = reopened.list(10);
        assertEquals(1, records.size());
        assertFalse(records.get(0).getTokenHash().contains("jwt-value-1"));

        reopened.remove("jwt-value-1");
        assertFalse(reopened.findByTokenValue("jwt-value-1").isPresent());
    }

    @Test
    void revokeDropsOnlyThatSubjectAtThatClient() throws Exception {
        DriverManagerConnectionSource source = new DriverManagerConnectionSource(
                "jdbc:sqlite:" + tempDir.resolve("legacy-tokens.db"), null, null);
        try (java.sql.Connection connection = source.openConnection()) {
            connection.createStatement().execute(
                    "CREATE TABLE picketlink_auth_tokens ("
                            + "token_hash VARCHAR(64) PRIMARY KEY, "
                            + "client_id VARCHAR(128) NOT NULL, "
                            + "scopes VARCHAR(1024), "
                            + "issued_at BIGINT NOT NULL, "
                            + "expires_at BIGINT NOT NULL)");
        }
        JdbcAccessTokenRegistry registry = new JdbcAccessTokenRegistry(source);
        Set<String> scopes = new LinkedHashSet<>();
        scopes.add("openid");
        Instant issued = Instant.now();
        Instant expires = issued.plusSeconds(300);
        registry.store(new AccessTokenRecord("alice-a", "client-a", scopes, issued, expires, "alice"));
        registry.store(new AccessTokenRecord("bob-a", "client-a", scopes, issued, expires, "bob"));
        registry.store(new AccessTokenRecord("alice-c", "client-c", scopes, issued, expires, "alice"));
        assertEquals("alice", registry.findByTokenValue("alice-a").get().getSubject());

        registry.revokeSubjectClient("alice", "client-a");

        assertFalse(registry.findByTokenValue("alice-a").isPresent());
        assertEquals("bob", registry.findByTokenValue("bob-a").get().getSubject());
        assertTrue(registry.findByTokenValue("alice-c").isPresent());
    }

    @Test
    void policyConfigShouldRoundTripAsJson() {
        IssuancePolicyConfig config = new IssuancePolicyConfig();
        config.setAllowedAlgorithms(new LinkedHashSet<>(List.of("RS256", "ES256")));
        config.setDefaultAlgorithm("ES256");
        config.setDefaultLifetimeSeconds(120L);
        config.setMaxLifetimeSeconds(900L);

        IssuancePolicyConfig loaded = IssuancePolicyConfig.fromJson(config.toJson());
        assertEquals("ES256", loaded.getDefaultAlgorithm());
        assertEquals(Set.of("RS256", "ES256"), loaded.getAllowedAlgorithms());
        assertEquals(120L, loaded.getDefaultLifetimeSeconds());
        assertEquals(900L, loaded.getMaxLifetimeSeconds());
    }

    private String jwksJson() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        RSAPublicKey rsa = (RSAPublicKey) pair.getPublic();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"client-key-1\",\"n\":\""
                + encoder.encodeToString(rsa.getModulus().toByteArray())
                + "\",\"e\":\"" + encoder.encodeToString(rsa.getPublicExponent().toByteArray())
                + "\"}]}";
    }
}
