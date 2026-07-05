package org.picketlink.idm.realm.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

public final class JsonFileIdmRealmConfigStore implements IdmRealmConfigStore {

    private final Path configFile;
    private final Object lock = new Object();

    public JsonFileIdmRealmConfigStore(Path configFile) {
        this.configFile = configFile;
    }

    public Path getConfigFile() {
        return configFile;
    }

    @Override
    public IdmRealmConfigDocument load() throws IOException {
        synchronized (lock) {
            if (!Files.exists(configFile)) {
                return IdmRealmConfigDocument.defaults();
            }
            String json = Files.readString(configFile, StandardCharsets.UTF_8);
            return IdmRealmConfigJsonCodec.read(json);
        }
    }

    @Override
    public IdmRealmConfigDocument save(IdmRealmConfigDocument document) throws IOException {
        synchronized (lock) {
            write(document);
            return document;
        }
    }

    private void write(IdmRealmConfigDocument document) throws IOException {
        Path parent = configFile.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path tempDirectory = parent == null ? Path.of(".") : parent;
        Path tempFile = Files.createTempFile(tempDirectory, "picketlink-realm-config-", ".json");
        Files.writeString(tempFile, IdmRealmConfigJsonCodec.write(document), StandardCharsets.UTF_8,
                StandardOpenOption.TRUNCATE_EXISTING);
        try {
            Files.move(tempFile, configFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ex) {
            Files.move(tempFile, configFile, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
