package org.picketlink.idm.admin.standalone;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StaxStandaloneXmlEditorTest {

    @TempDir
    Path tempDir;

    @Test
    void appliesOidcProfileWithMinimalDiff(@TempDir Path dir) throws Exception {
        Path standalone = dir.resolve("standalone.xml");
        Files.copy(getClass().getResourceAsStream("/sample-standalone.xml"), standalone);
        String before = Files.readString(standalone);

        StaxStandaloneXmlEditor editor = new StaxStandaloneXmlEditor();
        editor.apply(standalone, WildFlyConfigurationProfile.OIDC_AUTHORIZATION_SERVER.getInsertions());

        String after = Files.readString(standalone);
        assertTrue(after.contains("PicketLinkOidcAsElytronDomain"));
        assertTrue(after.contains("PicketLinkOidcIdmRealm"));
        assertTrue(after.contains("PicketLinkOidcAsDomain"));
        assertTrue(before.contains("<security-domains>"));
        assertTrue(after.contains("<security-domains>"));
        assertFalse(after.contains("PicketLinkTestElytronDomain"));
    }

    @Test
    void skipsDuplicateApplication(@TempDir Path dir) throws Exception {
        Path standalone = dir.resolve("standalone.xml");
        Files.copy(getClass().getResourceAsStream("/sample-standalone.xml"), standalone);
        StaxStandaloneXmlEditor editor = new StaxStandaloneXmlEditor();
        editor.apply(standalone, WildFlyConfigurationProfile.OIDC_AUTHORIZATION_SERVER.getInsertions());
        String once = Files.readString(standalone);
        editor.apply(standalone, WildFlyConfigurationProfile.OIDC_AUTHORIZATION_SERVER.getInsertions());
        String twice = Files.readString(standalone);
        assertTrue(once.equals(twice));
    }

    @Test
    void createsTimestampedBackup() throws Exception {
        Path standalone = tempDir.resolve("standalone.xml");
        Files.writeString(standalone, "<server/>");
        Path backup = StandaloneXmlBackup.createBackup(standalone);
        assertTrue(Files.exists(backup));
        assertTrue(backup.getFileName().toString().contains("standalone.xml.bak-"));
    }
}
