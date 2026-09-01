package org.picketlink.oidc.provider;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pushed Authorization Requests (RFC 9126): the client POSTs its authorization parameters
 * to the push endpoint (authenticated), receiving a one-time {@code request_uri}; the
 * browser then only carries {@code client_id} + {@code request_uri} to the authorization
 * endpoint. Nothing sensitive transits the front channel, and request-object/parameter
 * tampering is impossible — the pushed payload is immutable.
 */
public final class PushedAuthorizationRequestService {

    public static final String REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";
    public static final long DEFAULT_LIFETIME_SECONDS = 60L;

    private final ConcurrentHashMap<String, StoredRequest> byUri = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Clock clock;
    private final long lifetimeSeconds;

    public PushedAuthorizationRequestService(Clock clock) {
        this(clock, DEFAULT_LIFETIME_SECONDS);
    }

    public PushedAuthorizationRequestService(Clock clock, long lifetimeSeconds) {
        this.clock = clock;
        this.lifetimeSeconds = lifetimeSeconds;
    }

    /** Stores the authenticated client's pushed parameters; returns the request_uri value. */
    public String push(String clientId, Map<String, String> parameters) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String value = REQUEST_URI_PREFIX
                + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        byUri.put(value, new StoredRequest(clientId, new LinkedHashMap<>(parameters),
                clock.instant().getEpochSecond() + lifetimeSeconds));
        return value;
    }

    /**
     * Consumes the pushed request (single use, client-bound).
     *
     * @return the pushed parameters, or null when unknown, expired or bound to another client
     */
    public Map<String, String> consume(String requestUri, String clientId) {
        if (requestUri == null || !requestUri.startsWith(REQUEST_URI_PREFIX)) {
            return null;
        }
        StoredRequest stored = byUri.remove(requestUri);
        if (stored == null || !stored.clientId.equals(clientId)) {
            return null;
        }
        if (stored.expiresAt <= clock.instant().getEpochSecond()) {
            return null;
        }
        return stored.parameters;
    }

    public long lifetimeSeconds() {
        return lifetimeSeconds;
    }

    private static final class StoredRequest {

        final String clientId;
        final Map<String, String> parameters;
        final long expiresAt;

        StoredRequest(String clientId, Map<String, String> parameters, long expiresAt) {
            this.clientId = clientId;
            this.parameters = parameters;
            this.expiresAt = expiresAt;
        }
    }
}
