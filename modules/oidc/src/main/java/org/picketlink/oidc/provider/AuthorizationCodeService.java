package org.picketlink.oidc.provider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OIDC authorization codes: single-use, short-lived (default 60s), bound to client, redirect
 * URI, subject, scopes and a PKCE S256 challenge. Every client must send a challenge. The
 * verifier is 43 to 128 unreserved characters (RFC 7636). {@code plain} is rejected.
 */
public final class AuthorizationCodeService {

    public static final long DEFAULT_LIFETIME_SECONDS = 60L;
    public static final int VERIFIER_MIN_LENGTH = 43;
    public static final int VERIFIER_MAX_LENGTH = 128;

    private final ConcurrentHashMap<String, PendingCode> codes = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Clock clock;
    private final long lifetimeSeconds;

    public AuthorizationCodeService(Clock clock) {
        this(clock, DEFAULT_LIFETIME_SECONDS);
    }

    public AuthorizationCodeService(Clock clock, long lifetimeSeconds) {
        this.clock = clock;
        this.lifetimeSeconds = lifetimeSeconds;
    }

    public String create(String clientId, String redirectUri, String subject,
            String scopes, String nonce, String codeChallenge) {
        return create(clientId, redirectUri, subject, scopes, nonce, codeChallenge, null);
    }

    public String create(String clientId, String redirectUri, String subject,
            String scopes, String nonce, String codeChallenge, Long maxAge) {
        return create(clientId, redirectUri, subject, scopes, nonce, codeChallenge,
                maxAge, null, null);
    }

    /**
     * @param sid browser session id shared by every client in this SSO session; a fresh
     *        id is minted when the caller has no session
     * @param authTime original authentication time; null means authenticate now
     */
    public String create(String clientId, String redirectUri, String subject,
            String scopes, String nonce, String codeChallenge, Long maxAge,
            String sid, Long authTime) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        long authenticatedAt = authTime == null
                ? clock.instant().getEpochSecond() : authTime.longValue();
        String sessionId = sid == null || sid.isBlank()
                ? java.util.UUID.randomUUID().toString() : sid;
        codes.put(code, new PendingCode(clientId, redirectUri, subject, scopes, nonce,
                codeChallenge, clock.instant().getEpochSecond() + lifetimeSeconds,
                authenticatedAt, maxAge, sessionId));
        return code;
    }

    /** Drops every still-pending code for this browser session. Other sessions stay. */
    public void discardSid(String sid) {
        if (sid == null || sid.isBlank()) {
            return;
        }
        codes.entrySet().removeIf(entry -> sid.equals(entry.getValue().sid));
    }

    /**
     * Consumes the code (single use). A consumed, expired, or PKCE-failed code never validates again.
     * The code is removed before the verifier is checked, so a wrong verifier cannot be retried.
     */
    public Optional<PendingCode> consume(String code, String codeVerifier) {
        if (code == null) {
            return Optional.empty();
        }
        PendingCode pending = codes.remove(code);
        return redeem(pending, codeVerifier);
    }

    /**
     * Redeems a code for this client and redirect URI. A different client, or a different
     * redirect URI, leaves the code in place so a front-channel observer cannot burn it.
     * A matching client with a wrong verifier still consumes the code.
     */
    public Optional<PendingCode> consume(String code, String codeVerifier,
            String expectedClientId, String expectedRedirectUri) {
        if (code == null) {
            return Optional.empty();
        }
        PendingCode pending = codes.get(code);
        if (pending == null
                || expectedClientId == null || !expectedClientId.equals(pending.clientId)
                || expectedRedirectUri == null || !expectedRedirectUri.equals(pending.redirectUri)) {
            return Optional.empty();
        }
        if (!codes.remove(code, pending)) {
            return Optional.empty();
        }
        return redeem(pending, codeVerifier);
    }

    private Optional<PendingCode> redeem(PendingCode pending, String codeVerifier) {
        if (pending == null) {
            return Optional.empty();
        }
        if (pending.expiresAt <= clock.instant().getEpochSecond()) {
            return Optional.empty();
        }
        if (!verifierMatches(pending.codeChallenge, codeVerifier)) {
            return Optional.empty();
        }
        return Optional.of(pending);
    }

    /** True when the authorization request carries an S256 challenge of the RFC 7636 shape. */
    public static boolean s256ChallengeAccepted(String challenge, String method) {
        return "S256".equals(method) && challengeAccepted(challenge);
    }

    /** True when {@code verifier} is 43–128 unreserved ASCII characters (RFC 7636). */
    public static boolean verifierAccepted(String verifier) {
        if (verifier == null) {
            return false;
        }
        int length = verifier.length();
        if (length < VERIFIER_MIN_LENGTH || length > VERIFIER_MAX_LENGTH) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            char c = verifier.charAt(i);
            boolean unreserved = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~';
            if (!unreserved) {
                return false;
            }
        }
        return true;
    }

    static boolean verifierMatches(String challenge, String verifier) {
        if (!challengeAccepted(challenge) || !verifierAccepted(verifier)) {
            return false;
        }
        byte[] expected;
        try {
            expected = Base64.getUrlDecoder().decode(challenge + "=");
        } catch (IllegalArgumentException ex) {
            return false;
        }
        if (expected.length != 32) {
            return false;
        }
        return MessageDigest.isEqual(expected, sha256(verifier));
    }

    private static boolean challengeAccepted(String challenge) {
        if (challenge == null || challenge.length() != 43) {
            return false;
        }
        for (int i = 0; i < challenge.length(); i++) {
            char c = challenge.charAt(i);
            boolean base64Url = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
            if (!base64Url) {
                return false;
            }
        }
        return true;
    }

    private static byte[] sha256(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(verifier.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    public static String s256(String verifier) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(verifier));
    }

    /** Code payload: everything the token exchange must re-verify. */
    public static final class PendingCode {

        final String clientId;
        final String redirectUri;
        final String subject;
        final String scopes;
        final String nonce;
        final String codeChallenge;
        final long expiresAt;
        final long authTime;
        final Long maxAge;
        final String sid;

        PendingCode(String clientId, String redirectUri, String subject, String scopes,
                String nonce, String codeChallenge, long expiresAt, long authTime, Long maxAge,
                String sid) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.subject = subject;
            this.scopes = scopes;
            this.nonce = nonce;
            this.codeChallenge = codeChallenge;
            this.expiresAt = expiresAt;
            this.authTime = authTime;
            this.maxAge = maxAge;
            this.sid = sid;
        }

        public String getClientId() {
            return clientId;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public String getSubject() {
            return subject;
        }

        public String getScopes() {
            return scopes;
        }

        public String getNonce() {
            return nonce;
        }

        /** End-user authentication time (epoch seconds) for the ID token's auth_time. */
        public long getAuthTime() {
            return authTime;
        }

        /** Requested OIDC max_age (seconds), null when unset. */
        public Long getMaxAge() {
            return maxAge;
        }

        /** Browser SSO session id, copied into the ID token {@code sid} claim. */
        public String getSid() {
            return sid;
        }
    }
}
