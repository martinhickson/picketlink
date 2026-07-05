package org.picketlink.auth.oauth.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.picketlink.auth.oauth.client.store.JsonFileClientRegistrationStore;

class ClientRegistrationServiceTest {

    @TempDir
    Path tempDir;

    private ClientRegistrationService service;

    @BeforeEach
    void setUp() {
        service = new ClientRegistrationService(new JsonFileClientRegistrationStore(tempDir.resolve("clients.json")));
    }

    @Test
    void registersAndListsClients() {
        ClientRegistrationRequest request = new ClientRegistrationRequest();
        request.setClientId("service-a");
        request.getScopes().add("api.read");
        request.setTokenEndpointAuthMethod("client_secret_basic");

        ClientRegistrationView created = service.registerClient(request);

        assertEquals("service-a", created.getClientId());
        assertEquals(1, service.listClients().size());
        assertEquals("********", service.listClients().get(0).getClientSecret());
    }

    @Test
    void rejectsDuplicateClientIds() {
        ClientRegistrationRequest request = new ClientRegistrationRequest();
        request.setClientId("duplicate");
        service.registerClient(request);

        assertThrows(ClientRegistrationException.class, () -> service.registerClient(request));
    }
}
