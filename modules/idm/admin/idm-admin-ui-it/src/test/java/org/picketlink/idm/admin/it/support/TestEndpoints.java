package org.picketlink.idm.admin.it.support;

public final class TestEndpoints {

    private TestEndpoints() {
    }

    public static String baseUrl() {
        String configured = System.getProperty("test.base.url");
        if (configured != null && !configured.isBlank()) {
            return trimTrailingSlash(configured);
        }
        return "http://" + host() + ":" + httpPort() + "/idm-admin";
    }

    public static String host() {
        return System.getProperty("test.host", "127.0.0.112");
    }

    public static int httpPort() {
        return Integer.getInteger("test.http.port", 8180);
    }

    public static String jbossHome() {
        return System.getProperty("jboss.home");
    }

    private static String trimTrailingSlash(String url) {
        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }
}
