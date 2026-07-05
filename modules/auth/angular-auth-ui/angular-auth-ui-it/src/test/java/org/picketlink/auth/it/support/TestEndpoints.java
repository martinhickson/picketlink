package org.picketlink.auth.it.support;

public final class TestEndpoints {

    private TestEndpoints() {
    }

    public static String authBaseUrl() {
        String configured = System.getProperty("test.auth.base.url");
        if (configured != null && !configured.isBlank()) {
            return trimTrailingSlash(configured);
        }
        return "http://" + authHost() + ":" + httpPort() + "/auth";
    }

    public static String apiBaseUrl() {
        String configured = System.getProperty("test.api.base.url");
        if (configured != null && !configured.isBlank()) {
            return trimTrailingSlash(configured);
        }
        return "http://" + apiHost() + ":" + httpPort() + "/api";
    }

    public static String authHost() {
        return System.getProperty("test.auth.host", "127.0.0.110");
    }

    public static String apiHost() {
        return System.getProperty("test.api.host", "127.0.0.111");
    }

    public static int httpPort() {
        return Integer.getInteger("test.http.port", 8080);
    }

    private static String trimTrailingSlash(String url) {
        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }
}
