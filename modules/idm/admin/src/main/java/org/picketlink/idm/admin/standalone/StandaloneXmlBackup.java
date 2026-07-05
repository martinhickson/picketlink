package org.picketlink.idm.admin.standalone;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class StandaloneXmlBackup {

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmssSSS");

    private StandaloneXmlBackup() {
    }

    public static Path createBackup(Path standaloneXml) throws IOException {
        if (!Files.isRegularFile(standaloneXml)) {
            throw new IOException("standalone.xml not found: " + standaloneXml);
        }
        String backupName = standaloneXml.getFileName()
                + ".bak-" + LocalDateTime.now().format(TIMESTAMP);
        Path backup = standaloneXml.resolveSibling(backupName);
        Files.copy(standaloneXml, backup);
        return backup;
    }
}
