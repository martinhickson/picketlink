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
 * URI, subject, scopes and the PKCE challenge. PKCE is mandatory for public clients and
 * verified per RFC 7636 (S256 only; the insecure {@code plain} method is rejected).
 */
public final class AuthorizationCodeService {

    public static final long DEFAULT_LIFETIME_SECONDS = 60L;

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
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        codes.put(code, new PendingCode(clientId, redirectUri, subject, scopes, nonce,
                codeChallenge, clock.instant().getEpochSecond() + lifetimeSeconds));
        return code;
    }

    /**
     * Consumes the code (single use). A consumed or expired code never validates again.
     *
     * @param codeVerifier PKCE verifier; required when the authorization request carried a challenge
     */
    public Optional<PendingCode> consume(String code, String codeVerifier) {
        if (code == null) {
            return Optional.empty();
        }
        PendingCode pending = codes.remove(code);
        if (pending == null) {
            return Optional.empty();
        }
        if (pending.expiresAt <= clock.instant().getEpochSecond()) {
            return Optional.empty();
        }
        if (pending.codeChallenge != null) {
            if (codeVerifier == null || !pending.codeChallenge.equals(s256(codeVerifier))) {
                return Optional.empty();
            }
        }
        return Optional.of(pending);
    }

    public static String s256(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(verifier.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
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

        PendingCode(String clientId, String redirectUri, String subject, String scopes,
                String nonce, String codeChallenge, long expiresAt) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.subject = subject;
            this.scopes = scopes;
            this.nonce = nonce;
            this.codeChallenge = codeChallenge;
            this.expiresAt = expiresAt;
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
    }
}
