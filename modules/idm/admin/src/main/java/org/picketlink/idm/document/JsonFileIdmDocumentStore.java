package org.picketlink.idm.document;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

/**
 * Default {@link IdmDocumentStore}: one JSON file per document id with optimistic locking on the
 * envelope {@code version} field (same contract as {@link JdbcClobIdmDocumentStore}).
 *
 * <p>Pass a directory to store {@code {documentId}.json} files, or a {@code .json} file path for a
 * single-document store (default: {@code .../configuration/security/picketlink-db.json}).
 */
public final class JsonFileIdmDocumentStore implements IdmDocumentStore {

    private final Path storagePath;
    private final boolean directoryMode;
    private final Object lock = new Object();

    public JsonFileIdmDocumentStore(Path storagePath) {
        this(storagePath, isDirectoryStorage(storagePath));
    }

    JsonFileIdmDocumentStore(Path storagePath, boolean directoryMode) {
        this.storagePath = storagePath;
        this.directoryMode = directoryMode;
    }

    @Override
    public IdmRealmDocument load(String documentId) throws IOException {
        synchronized (lock) {
            Path file = fileFor(documentId);
            if (!Files.exists(file)) {
                return IdmRealmDocument.empty(documentId);
            }
            String json = Files.readString(file, StandardCharsets.UTF_8);
            return IdmDocumentJsonCodec.read(documentId, json);
        }
    }

    @Override
    public IdmRealmDocument save(IdmRealmDocument document, long expectedVersion) throws IOException {
        synchronized (lock) {
            IdmRealmDocument current = load(document.getDocumentId());
            if (current.getVersion() != expectedVersion) {
                throw new OptimisticLockException(document.getDocumentId(), expectedVersion, current.getVersion());
            }
            if (document.getVersion() != expectedVersion + 1L) {
                throw new IllegalArgumentException("Saved document version must be expectedVersion + 1");
            }
            write(document);
            return document;
        }
    }

    public Path getStoragePath() {
        return storagePath;
    }

    /** @deprecated use {@link #getStoragePath()} */
    @Deprecated
    public Path getDirectory() {
        return directoryMode ? storagePath : storagePath.getParent();
    }

    private Path fileFor(String documentId) {
        if (directoryMode) {
            return storagePath.resolve(sanitize(documentId) + ".json");
        }
        return storagePath;
    }

    private void write(IdmRealmDocument document) throws IOException {
        Path file = fileFor(document.getDocumentId());
        Path parent = directoryMode ? storagePath : file.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path tempDirectory = parent == null ? Path.of(".") : parent;
        Path tempFile = Files.createTempFile(tempDirectory, document.getDocumentId() + "-", ".json");
        Files.writeString(tempFile, IdmDocumentJsonCodec.write(document), StandardCharsets.UTF_8,
                StandardOpenOption.TRUNCATE_EXISTING);
        try {
            Files.move(tempFile, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ex) {
            Files.move(tempFile, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static boolean isDirectoryStorage(Path path) {
        return !path.getFileName().toString().endsWith(".json");
    }

    private static String sanitize(String documentId) {
        return documentId.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
