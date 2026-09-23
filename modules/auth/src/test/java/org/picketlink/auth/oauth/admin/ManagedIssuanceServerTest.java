package org.picketlink.auth.oauth.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.model.TokenResponse;
import org.picketlink.auth.oauth.service.JwtClientCredentialsTokenService;
import org.picketlink.auth.oauth.store.DriverManagerConnectionSource;

class ManagedIssuanceServerTest {

    private static final String ISSUER = "https://auth.example.test";

    @TempDir
    Path tempDir;

    @Test
    void shouldAssembleEndToEndWithJdbcStores() throws Exception {
        System.setProperty("picketlink.auth.keystore.path",
                tempDir.resolve("keys.p12").toString());
        try {
            ManagedIssuanceServer server = ManagedIssuanceServer.builder(ISSUER)
                    .connectionSource(new DriverManagerConnectionSource(
                            "jdbc:sqlite:" + tempDir.resolve("managed-server.db"), null, null))
                    .build();

            // admin client seeded with auth-admin scope
            Optional<RegisteredClient> admin = server.getClientStore()
                    .findByClientId(ManagedIssuanceServer.ADMIN_CLIENT_ID);
            assertTrue(admin.isPresent());
            assertTrue(admin.get().getScopes().contains(AdminScopeFilter.ADMIN_SCOPE));

            // mint an admin token through the token endpoint service
            JwtClientCredentialsTokenService tokenService = server.getTokenService();
            TokenResponse response = tokenService.issueToken(TokenRequest.builder()
                    .grantType("client_credentials")
                    .authorizationHeader("Basic " + java.util.Base64.getEncoder()
                            .encodeToString((ManagedIssuanceServer.ADMIN_CLIENT_ID + ":"
                                    + admin.get().getClientSecret()).getBytes()))
                    .build());
            assertNotNull(response.getAccessToken());

            // the token validates through the manager and carries the admin scope
            Object scope = server.getIssuanceManager().validate(response.getAccessToken())
                    .getClaim(org.picketlink.auth.oauth.issuance.JwtIssuanceManager.CLAIM_SCOPE);
            assertEquals(AdminScopeFilter.ADMIN_SCOPE, scope);

            // admin resources are registered, incl. token browser for the JDBC registry
            assertTrue(server.getAdminResources().size() >= 3);
            assertEquals(4, server.getAdminResources().size());
        } finally {
            System.clearProperty("picketlink.auth.keystore.path");
        }
    }

    @Test
    void generatedAdminSecretIsNotWrittenToTheLog() throws Exception {
        Logger logger = Logger.getLogger(ManagedIssuanceServer.class.getName());
        List<String> lines = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                StringBuilder text = new StringBuilder();
                if (record.getMessage() != null) {
                    text.append(record.getMessage());
                }
                if (record.getParameters() != null) {
                    for (Object parameter : record.getParameters()) {
                        text.append(' ').append(parameter);
                    }
                }
                lines.add(text.toString());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        handler.setLevel(Level.ALL);
        Level previous = logger.getLevel();
        logger.setLevel(Level.ALL);
        logger.addHandler(handler);
        try {
            ManagedIssuanceServer server = ManagedIssuanceServer.builder(ISSUER).build();
            String secret = server.getClientStore()
                    .findByClientId(ManagedIssuanceServer.ADMIN_CLIENT_ID)
                    .get().getClientSecret();
            String logged = String.join("\n", lines);
            assertFalse(logged.contains(secret));
            assertTrue(logged.contains(ManagedIssuanceServer.ADMIN_CLIENT_SECRET_ENV));
            assertTrue(logged.contains(ManagedIssuanceServer.ADMIN_CLIENT_ID));
        } finally {
            logger.removeHandler(handler);
            logger.setLevel(previous);
        }
    }

    @Test
    void shouldFallBackToEphemeralSigningKeyWithoutJdbc() throws Exception {
        ManagedIssuanceServer server = ManagedIssuanceServer.builder(ISSUER).build();
        TokenResponse response = server.getTokenService().issueToken(TokenRequest.builder()
                .grantType("client_credentials")
                .authorizationHeader("Basic " + java.util.Base64.getEncoder().encodeToString(
                        (ManagedIssuanceServer.ADMIN_CLIENT_ID + ":"
                                + server.getClientStore()
                                        .findByClientId(ManagedIssuanceServer.ADMIN_CLIENT_ID)
                                        .get().getClientSecret()).getBytes()))
                .build());
        assertNotNull(server.getIssuanceManager().validate(response.getAccessToken()));
    }
}
