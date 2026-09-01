package org.picketlink.oidc.provider;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Device Authorization Grant state (RFC 8628): a device displays a short user code and a
 * verification URI; the user approves on a logged-in page; the device polls the token
 * endpoint with the device code until the grant is approved, denied or expired.
 */
public final class DeviceAuthorizationService {

    public static final long DEFAULT_LIFETIME_SECONDS = 600L;
    public static final long DEFAULT_POLL_INTERVAL_SECONDS = 5L;

    /** RFC 8628 §3.4 error codes surfaced at the token endpoint. */
    public static final String ERROR_AUTHORIZATION_PENDING = "authorization_pending";
    public static final String ERROR_SLOW_DOWN = "slow_down";
    public static final String ERROR_EXPIRED_TOKEN = "expired_token";
    public static final String ERROR_ACCESS_DENIED = "access_denied";

    /** Lifecycle of a device grant. */
    public enum Status {
        PENDING,
        APPROVED,
        DENIED,
        CONSUMED
    }

    private final ConcurrentHashMap<String, DeviceGrant> byDeviceCode = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, DeviceGrant> byUserCode = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Clock clock;
    private final long lifetimeSeconds;
    private final long pollIntervalSeconds;

    public DeviceAuthorizationService(Clock clock) {
        this(clock, DEFAULT_LIFETIME_SECONDS, DEFAULT_POLL_INTERVAL_SECONDS);
    }

    public DeviceAuthorizationService(Clock clock, long lifetimeSeconds, long pollIntervalSeconds) {
        this.clock = clock;
        this.lifetimeSeconds = lifetimeSeconds;
        this.pollIntervalSeconds = pollIntervalSeconds;
    }

    /** Creates a pending device grant and returns it for the endpoint response. */
    public DeviceGrant create(String clientId, String scopes) {
        byte[] deviceBytes = new byte[32];
        random.nextBytes(deviceBytes);
        String deviceCode = Base64.getUrlEncoder().withoutPadding().encodeToString(deviceBytes);
        String userCode = generateUserCode();
        DeviceGrant grant = new DeviceGrant(deviceCode, userCode, clientId, scopes,
                clock.instant().getEpochSecond() + lifetimeSeconds, Status.PENDING);
        byDeviceCode.put(deviceCode, grant);
        byUserCode.put(userCode, grant);
        return grant;
    }

    /** The logged-in user approves or denies a device after entering its user code. */
    public boolean decide(String userCode, String subject, boolean approved) {
        DeviceGrant grant = byUserCode.get(normalize(userCode));
        if (grant == null || isExpired(grant) || grant.status != Status.PENDING) {
            return false;
        }
        grant.status = approved ? Status.APPROVED : Status.DENIED;
        grant.subject = subject;
        return true;
    }

    /**
     * The device polls: returns the grant when approved (and marks it consumed — device
     * codes are single use per token issuance), or the pending/denied/expired state.
     */
    public Optional<DeviceGrant> poll(String deviceCode, String clientId) {
        DeviceGrant grant = byDeviceCode.get(deviceCode);
        if (grant == null || !grant.clientId.equals(clientId)) {
            return Optional.empty();
        }
        if (isExpired(grant)) {
            byDeviceCode.remove(deviceCode);
            byUserCode.remove(grant.userCode);
            return Optional.empty();
        }
        if (grant.status == Status.APPROVED) {
            grant.status = Status.CONSUMED;
            byDeviceCode.remove(deviceCode);
            byUserCode.remove(grant.userCode);
            return Optional.of(grant);
        }
        if (grant.status == Status.DENIED) {
            byDeviceCode.remove(deviceCode);
            byUserCode.remove(grant.userCode);
            grant.status = Status.DENIED; // surfaced once to the polling device
            return Optional.of(grant);
        }
        return Optional.of(grant); // still PENDING
    }

    public long pollIntervalSeconds() {
        return pollIntervalSeconds;
    }

    public long lifetimeSeconds() {
        return lifetimeSeconds;
    }

    private boolean isExpired(DeviceGrant grant) {
        return grant.expiresAt <= clock.instant().getEpochSecond();
    }

    /** RFC 8628 user codes: uppercase, no confusing characters (0/O, 1/I). */
    private String generateUserCode() {
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            code.append(alphabet.charAt(random.nextInt(alphabet.length())));
            if (i == 3) {
                code.append('-');
            }
        }
        return code.toString();
    }

    private static String normalize(String userCode) {
        return userCode == null ? "" : userCode.trim().toUpperCase().replace(" ", "");
    }

    /** A device grant's state as returned by {@link #create} and {@link #poll}. */
    public static final class DeviceGrant {

        final String deviceCode;
        final String userCode;
        final String clientId;
        final String scopes;
        final long expiresAt;
        volatile Status status;
        volatile String subject;

        DeviceGrant(String deviceCode, String userCode, String clientId, String scopes,
                long expiresAt, Status status) {
            this.deviceCode = deviceCode;
            this.userCode = userCode;
            this.clientId = clientId;
            this.scopes = scopes;
            this.expiresAt = expiresAt;
            this.status = status;
        }

        public String getDeviceCode() {
            return deviceCode;
        }

        public String getUserCode() {
            return userCode;
        }

        public String getScopes() {
            return scopes;
        }

        public Status getStatus() {
            return status;
        }

        public String getSubject() {
            return subject;
        }
    }
}
