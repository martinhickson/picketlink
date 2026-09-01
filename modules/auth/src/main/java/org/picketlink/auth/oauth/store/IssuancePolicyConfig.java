package org.picketlink.auth.oauth.store;

import java.util.LinkedHashSet;
import java.util.Set;

import org.picketlink.auth.oauth.json.OAuthJsonWriter;

/**
 * Persisted issuance policy configuration rendered as JSON in a CLOB. Mirrors what the
 * {@code IssuancePolicyEngine} enforces: allowed signing algorithms, default lifetime and the
 * server-wide lifetime cap.
 */
public final class IssuancePolicyConfig {

    public static final Set<String> DEFAULT_ALLOWED_ALGORITHMS = Set.of("RS256", "ES256");
    public static final long DEFAULT_LIFETIME_SECONDS = 300L;
    public static final long DEFAULT_MAX_LIFETIME_SECONDS = 600L;

    private Set<String> allowedAlgorithms;
    private String defaultAlgorithm = "RS256";
    private long defaultLifetimeSeconds = DEFAULT_LIFETIME_SECONDS;
    private long maxLifetimeSeconds = DEFAULT_MAX_LIFETIME_SECONDS;

    public Set<String> getAllowedAlgorithms() {
        return allowedAlgorithms;
    }

    public void setAllowedAlgorithms(Set<String> allowedAlgorithms) {
        this.allowedAlgorithms = allowedAlgorithms == null
                ? new LinkedHashSet<>()
                : new LinkedHashSet<>(allowedAlgorithms);
    }

    public String getDefaultAlgorithm() {
        return defaultAlgorithm;
    }

    public void setDefaultAlgorithm(String defaultAlgorithm) {
        this.defaultAlgorithm = defaultAlgorithm;
    }

    public long getDefaultLifetimeSeconds() {
        return defaultLifetimeSeconds;
    }

    public void setDefaultLifetimeSeconds(long defaultLifetimeSeconds) {
        this.defaultLifetimeSeconds = defaultLifetimeSeconds;
    }

    public long getMaxLifetimeSeconds() {
        return maxLifetimeSeconds;
    }

    public void setMaxLifetimeSeconds(long maxLifetimeSeconds) {
        this.maxLifetimeSeconds = maxLifetimeSeconds;
    }

    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append('{');
        json.append("\"defaultAlgorithm\":\"").append(OAuthJsonWriter.escape(defaultAlgorithm)).append('"');
        json.append(",\"defaultLifetimeSeconds\":").append(defaultLifetimeSeconds);
        json.append(",\"maxLifetimeSeconds\":").append(maxLifetimeSeconds);
        json.append(",\"allowedAlgorithms\":[");
        int i = 0;
        for (String algorithm : allowedAlgorithms) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(OAuthJsonWriter.escape(algorithm)).append('"');
            i++;
        }
        json.append("]}");
        return json.toString();
    }

    public static IssuancePolicyConfig fromJson(String json) {
        IssuancePolicyConfig config = new IssuancePolicyConfig();
        config.setAllowedAlgorithms(DEFAULT_ALLOWED_ALGORITHMS);
        if (json == null || json.isBlank()) {
            return config;
        }
        config.setDefaultAlgorithm(readString(json, "defaultAlgorithm", "RS256"));
        config.setDefaultLifetimeSeconds(readLong(json, "defaultLifetimeSeconds",
                DEFAULT_LIFETIME_SECONDS));
        config.setMaxLifetimeSeconds(readLong(json, "maxLifetimeSeconds",
                DEFAULT_MAX_LIFETIME_SECONDS));
        Set<String> algorithms = new LinkedHashSet<>();
        int arrayStart = json.indexOf("[");
        int arrayEnd = json.indexOf("]", arrayStart >= 0 ? arrayStart : 0);
        if (arrayStart >= 0 && arrayEnd > arrayStart) {
            String arrayJson = json.substring(arrayStart + 1, arrayEnd);
            int index = 0;
            while (index < arrayJson.length()) {
                int quoteStart = arrayJson.indexOf('"', index);
                if (quoteStart < 0) {
                    break;
                }
                int quoteEnd = arrayJson.indexOf('"', quoteStart + 1);
                if (quoteEnd < 0) {
                    break;
                }
                algorithms.add(arrayJson.substring(quoteStart + 1, quoteEnd));
                index = quoteEnd + 1;
            }
        }
        if (!algorithms.isEmpty()) {
            config.setAllowedAlgorithms(algorithms);
        }
        return config;
    }

    private static String readString(String json, String field, String fallback) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return fallback;
        }
        int quoteStart = json.indexOf('"', fieldIndex + marker.length());
        int quoteEnd = quoteStart >= 0 ? json.indexOf('"', quoteStart + 1) : -1;
        if (quoteStart < 0 || quoteEnd < 0) {
            return fallback;
        }
        return json.substring(quoteStart + 1, quoteEnd);
    }

    private static long readLong(String json, String field, long fallback) {
        String marker = "\"" + field + "\"";
        int fieldIndex = json.indexOf(marker);
        if (fieldIndex < 0) {
            return fallback;
        }
        int colon = json.indexOf(':', fieldIndex + marker.length());
        if (colon < 0) {
            return fallback;
        }
        int end = colon + 1;
        while (end < json.length() && Character.isDigit(json.charAt(end))) {
            end++;
        }
        return end == colon + 1 ? fallback : Long.parseLong(json.substring(colon + 1, end).trim());
    }
}
