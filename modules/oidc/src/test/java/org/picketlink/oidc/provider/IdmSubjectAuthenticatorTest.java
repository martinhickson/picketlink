package org.picketlink.oidc.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.config.IdentityConfigurationBuilder;
import org.picketlink.idm.credential.Credentials;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.credential.UsernamePasswordCredentials;
import org.picketlink.idm.internal.DefaultPartitionManager;
import org.picketlink.idm.model.basic.Realm;
import org.picketlink.idm.model.basic.User;

/**
 * IDM-backed OIDC authentication: passwords verified through the IDM credential pipeline and
 * standard OIDC profile claims (email, name, ...) derived from the IDM user.
 */
class IdmSubjectAuthenticatorTest {

    private IdmSubjectAuthenticator authenticator;

    @BeforeEach
    void setUp() throws Exception {
        IdentityConfigurationBuilder builder = new IdentityConfigurationBuilder();
        builder.named("default").stores().file()
                .workingDirectory(java.nio.file.Files.createTempDirectory("plk-oidc-idm").toString())
                .supportAllFeatures();
        PartitionManager partitionManager = new DefaultPartitionManager(builder.build());
        Realm defaultRealm = partitionManager.<Realm>getPartition(Realm.class, Realm.DEFAULT_REALM);
        if (defaultRealm == null) {
            defaultRealm = new Realm(Realm.DEFAULT_REALM);
            partitionManager.add(defaultRealm);
        }
        org.picketlink.idm.IdentityManager identityManager =
                partitionManager.createIdentityManager(defaultRealm);

        User alice = new User("alice");
        alice.setEmail("alice@corp.example");
        alice.setFirstName("Alice");
        alice.setLastName("Anderson");
        identityManager.add(alice);
        identityManager.updateCredential(alice, new Password("wonderland"));

        authenticator = new IdmSubjectAuthenticator(identityManager);
    }

    @Test
    void shouldAuthenticateValidIdmUser() {
        Optional<String> subject = authenticator.authenticate("alice", "wonderland");
        assertTrue(subject.isPresent());
        assertEquals("alice", subject.get());
    }

    @Test
    void shouldRejectWrongPassword() {
        assertFalse(authenticator.authenticate("alice", "wrong").isPresent());
    }

    @Test
    void shouldRejectUnknownUser() {
        assertFalse(authenticator.authenticate("mallory", "wonderland").isPresent());
    }

    @Test
    void shouldRejectBlankInput() {
        assertFalse(authenticator.authenticate(null, "wonderland").isPresent());
        assertFalse(authenticator.authenticate("alice", null).isPresent());
        assertFalse(authenticator.authenticate(" ", "x").isPresent());
    }

    @Test
    void shouldDeriveOidcProfileClaimsFromIdmUser() {
        Map<String, String> claims = authenticator.claimsFor("alice");
        assertEquals("alice@corp.example", claims.get("email"));
        assertEquals("Alice Anderson", claims.get("name"));
        assertEquals("Alice", claims.get("given_name"));
        assertEquals("Anderson", claims.get("family_name"));
        assertEquals("alice", claims.get("preferred_username"));
    }

    @Test
    void shouldReturnNoClaimsForUnknownSubject() {
        assertTrue(authenticator.claimsFor("nobody").isEmpty());
    }
}
