package org.picketlink.idm.admin.standalone;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.picketlink.idm.document.IdmDocumentStores;
import org.picketlink.idm.document.IdmRealmDocument;
import org.picketlink.idm.document.IdmRealmService;
import org.picketlink.idm.document.JsonFileIdmDocumentStore;

public final class StandaloneConfigurationService {

    private final StaxStandaloneXmlEditor editor = new StaxStandaloneXmlEditor();

    public StandaloneConfigurationResult applyProfile(Path jbossHome, WildFlyConfigurationProfile profile,
            boolean removeHttpsListener) throws IOException {
        Path configDir = jbossHome.resolve("standalone/configuration");
        Path standaloneXml = configDir.resolve("standalone.xml");
        List<String> messages = new ArrayList<String>();

        if (!profile.isMutatesStandaloneXml()) {
            messages.add(profile.getDescription());
            messages.add("No standalone.xml edits were applied for this profile.");
            return new StandaloneConfigurationResult(profile, standaloneXml, standaloneXml, false, 0, messages);
        }

        Path backup = StandaloneXmlBackup.createBackup(standaloneXml);
        messages.add("Created timestamped backup: " + backup.getFileName());

        writeCredentialFiles(configDir, profile);
        if (profile == WildFlyConfigurationProfile.SAML) {
            messages.add("Wrote picketlink-users.properties and picketlink-roles.properties under configuration/.");
        }
        if (profile == WildFlyConfigurationProfile.OIDC_AUTHORIZATION_SERVER) {
            seedOidcRealmDocument(configDir);
            messages.add("Seeded configuration/security/picketlink-db.json with default OIDC AS user "
                    + "(user1/password1) when empty.");
        }

        if (profile == WildFlyConfigurationProfile.SAML) {
            writeSpLoginConf(configDir);
            messages.add("Wrote picketlink-sp.login.conf for SAML SP JAAS login module.");
        }

        copyTestKeystore(configDir);

        editor.apply(standaloneXml, profile.getInsertions());
        messages.add("Applied Elytron and Undertow fragments from " + profile.getId() + " using Woodstox StAX "
                + "(minimal diff — unchanged regions preserve original formatting).");

        int httpsRemoved = 0;
        if (removeHttpsListener) {
            httpsRemoved = editor.removeHttpsListeners(standaloneXml);
            if (httpsRemoved > 0) {
                messages.add("Removed " + httpsRemoved + " https-listener element(s) for local HTTP demo use.");
            }
        }

        if (profile.isRequiresWildFlyModule()) {
            messages.add("Install the org.picketlink WildFly module, then restart WildFly.");
        }
        messages.add("Restart WildFly to load Elytron subsystem changes.");

        StandaloneConfigurationResult handoff = new StandaloneConfigurationResult(
                profile, standaloneXml, backup, true, httpsRemoved, messages);
        messages = new ArrayList<String>(handoff.getMessages());
        messages.add(handoff.getDeployerHandoffNote());

        return new StandaloneConfigurationResult(profile, standaloneXml, backup, true, httpsRemoved, messages);
    }

    private static void writeCredentialFiles(Path configDir, WildFlyConfigurationProfile profile) throws IOException {
        if (profile != WildFlyConfigurationProfile.SAML) {
            return;
        }
        Files.createDirectories(configDir);
        Files.writeString(configDir.resolve("picketlink-users.properties"), "user1=password1\n");
        Files.writeString(configDir.resolve("picketlink-roles.properties"), "user1=role1\n");
    }

    private static void seedOidcRealmDocument(Path configDir) throws IOException {
        Path realmFile = configDir.resolve("security").resolve("picketlink-db.json");
        Files.createDirectories(realmFile.getParent());
        JsonFileIdmDocumentStore fileStore = new JsonFileIdmDocumentStore(realmFile);
        IdmRealmService realmService = new IdmRealmService(fileStore);
        IdmRealmDocument current = fileStore.load(IdmDocumentStores.DEFAULT_DOCUMENT_ID);
        if (current.getVersion() == 0L && current.getUsers().isEmpty()) {
            realmService.createUser(IdmDocumentStores.DEFAULT_DOCUMENT_ID, 0L, "user1", "password1",
                    java.util.List.of("role1"));
        }
    }

    private static void writeSpLoginConf(Path configDir) throws IOException {
        Files.writeString(configDir.resolve("picketlink-sp.login.conf"),
                "PicketLinkSP {\n"
                        + "    org.picketlink.identity.federation.bindings.wildfly.SAML2LoginModule required;\n"
                        + "};\n");
    }

    private static void copyTestKeystore(Path configDir) throws IOException {
        Path keystoreTarget = configDir.resolve("jbid_test_keystore.jks");
        if (Files.exists(keystoreTarget)) {
            return;
        }
        try (InputStream keystore = StandaloneConfigurationService.class.getResourceAsStream("/jbid_test_keystore.jks")) {
            if (keystore == null) {
                return;
            }
            Files.copy(keystore, keystoreTarget);
        }
    }
}
