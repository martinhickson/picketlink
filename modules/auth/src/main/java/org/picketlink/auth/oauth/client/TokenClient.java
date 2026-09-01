package org.picketlink.auth.oauth.client;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;

import org.picketlink.auth.oauth.OAuthConstants;

/**
 * Machine-to-machine token endpoint client — the piece of JWT work that quietly eats
 * everyone's afternoon: fetching tokens, caching them, refreshing before expiry, doing it
 * thread-safely. One class, no dependencies beyond the JDK.
 *
 * <pre>{@code
 * TokenClient client = TokenClient.forClientCredentials(
 *         "https://auth.example/oauth/token", "my-client", "my-secret");
 * String token = client.token();          // cached; refreshed ~30s before expiry
 * }</pre>
 *
 * Thread-safe: concurrent callers share one in-flight refresh.
 */
public final class TokenClient {

    private static final long DEFAULT_REFRESH_AHEAD_SECONDS = 30L;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final String scope;
    private final Clock clock;

    private final Object lock = new Object();
    private String cachedToken;
    private long expiresAtEpochSeconds;

    private TokenClient(String tokenEndpoint, String clientId, String clientSecret, String scope,
            Clock clock) {
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scope = scope;
        this.clock = clock;
    }

    public static TokenClient forClientCredentials(String tokenEndpoint, String clientId,
            String clientSecret) {
        return new TokenClient(tokenEndpoint, clientId, clientSecret, null, Clock.systemUTC());
    }

    public static TokenClient forClientCredentials(String tokenEndpoint, String clientId,
            String clientSecret, String scope) {
        return new TokenClient(tokenEndpoint, clientId, clientSecret, scope, Clock.systemUTC());
    }

    TokenClient withClock(Clock clock) {
        return new TokenClient(tokenEndpoint, clientId, clientSecret, scope, clock);
    }

    /** @return a valid access token, cached and refreshed ahead of expiry */
    public String token() throws IOException, InterruptedException {
        synchronized (lock) {
            if (cachedToken != null
                    && clock.instant().getEpochSecond() < expiresAtEpochSeconds - DEFAULT_REFRESH_AHEAD_SECONDS) {
                return cachedToken;
            }
            TokenResponse response = fetch();
            this.cachedToken = response.accessToken;
            this.expiresAtEpochSeconds = clock.instant().getEpochSecond() + response.expiresIn;
            return cachedToken;
        }
    }

    /** Forces the next {@link #token()} call to fetch a fresh token (e.g. after a 401). */
    public void invalidate() {
        synchronized (lock) {
            cachedToken = null;
        }
    }

    private TokenResponse fetch() throws IOException, InterruptedException {
        StringBuilder body = new StringBuilder("grant_type=")
                .append(OAuthConstants.CLIENT_CREDENTIALS_GRANT);
        if (scope != null && !scope.isBlank()) {
            body.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
        }
        HttpRequest request = HttpRequest.newBuilder(URI.create(tokenEndpoint))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", OAuthConstants.APPLICATION_FORM_URLENCODED)
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8)))
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Token request failed: HTTP " + response.statusCode()
                    + " " + response.body());
        }
        String accessToken = readString(response.body(), OAuthConstants.ACCESS_TOKEN);
        long expiresIn = readNumber(response.body(), OAuthConstants.EXPIRES_IN);
        if (accessToken == null || expiresIn <= 0) {
            throw new IOException("Malformed token response");
        }
        return new TokenResponse(accessToken, expiresIn);
    }

    private static String readString(String json, String field) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return null;
        }
        int quoteStart = json.indexOf('"', fieldIndex + marker.length());
        int quoteEnd = quoteStart >= 0 ? json.indexOf('"', quoteStart + 1) : -1;
        if (quoteStart < 0 || quoteEnd < 0) {
            return null;
        }
        return json.substring(quoteStart + 1, quoteEnd);
    }

    private static long readNumber(String json, String field) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return 0L;
        }
        int colon = json.indexOf(':', fieldIndex + marker.length());
        if (colon < 0) {
            return 0L;
        }
        int end = colon + 1;
        while (end < json.length() && Character.isDigit(json.charAt(end))) {
            end++;
        }
        return end == colon + 1 ? 0L : Long.parseLong(json.substring(colon + 1, end).trim());
    }

    private static final class TokenResponse {

        final String accessToken;
        final long expiresIn;

        TokenResponse(String accessToken, long expiresIn) {
            this.accessToken = accessToken;
            this.expiresIn = expiresIn;
        }
    }
}
