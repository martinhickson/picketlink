package org.picketlink.auth.oauth.client.store;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.picketlink.auth.oauth.model.RegisteredClient;

public class JsonFileClientRegistrationStore implements ClientRegistrationStore {

    private final Path filePath;
    private final Object lock = new Object();

    public JsonFileClientRegistrationStore(Path filePath) {
        this.filePath = filePath;
    }

    @Override
    public List<RegisteredClient> findAll() {
        synchronized (lock) {
            return new ArrayList<RegisteredClient>(readClients());
        }
    }

    @Override
    public Optional<RegisteredClient> findByClientId(String clientId) {
        if (clientId == null) {
            return Optional.empty();
        }
        synchronized (lock) {
            for (RegisteredClient client : readClients()) {
                if (clientId.equals(client.getClientId())) {
                    return Optional.of(client);
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public void save(RegisteredClient client) {
        synchronized (lock) {
            List<RegisteredClient> clients = readClients();
            List<RegisteredClient> updated = new ArrayList<RegisteredClient>();
            boolean replaced = false;
            for (RegisteredClient existing : clients) {
                if (existing.getClientId().equals(client.getClientId())) {
                    updated.add(client);
                    replaced = true;
                } else {
                    updated.add(existing);
                }
            }
            if (!replaced) {
                updated.add(client);
            }
            writeClients(updated);
        }
    }

    @Override
    public boolean delete(String clientId) {
        if (clientId == null) {
            return false;
        }
        synchronized (lock) {
            List<RegisteredClient> clients = readClients();
            List<RegisteredClient> updated = new ArrayList<RegisteredClient>();
            boolean removed = false;
            for (RegisteredClient existing : clients) {
                if (existing.getClientId().equals(clientId)) {
                    removed = true;
                } else {
                    updated.add(existing);
                }
            }
            if (removed) {
                writeClients(updated);
            }
            return removed;
        }
    }

    public Path getFilePath() {
        return filePath;
    }

    private List<RegisteredClient> readClients() {
        try {
            if (!Files.exists(filePath)) {
                return new ArrayList<RegisteredClient>();
            }
            String json = Files.readString(filePath, StandardCharsets.UTF_8);
            return ClientRegistrationJsonCodec.read(json);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to read client registrations from " + filePath, ex);
        }
    }

    private void writeClients(List<RegisteredClient> clients) {
        try {
            Path parent = filePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tempFile = Files.createTempFile(parent == null ? filePath.getParent() : parent,
                    "picketlink-auth-clients-", ".json");
            Files.writeString(tempFile, ClientRegistrationJsonCodec.write(clients), StandardCharsets.UTF_8,
                    StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.move(tempFile, filePath, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(tempFile, filePath, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to write client registrations to " + filePath, ex);
        }
    }
}
