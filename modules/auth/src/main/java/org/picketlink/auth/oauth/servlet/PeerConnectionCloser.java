package org.picketlink.auth.oauth.servlet;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Drops the current HTTP connection without a status line or body. Undertow exposes the
 * connection on its request implementation; other containers are left untouched so the
 * caller does not turn the drop into an error response.
 */
public final class PeerConnectionCloser {

    private PeerConnectionCloser() {
    }

    public static boolean close(HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        try {
            Class<?> implementation = Class.forName("io.undertow.servlet.spec.HttpServletRequestImpl");
            if (!implementation.isInstance(request)) {
                return false;
            }
            Object exchange = implementation.getMethod("getExchange").invoke(request);
            Object connection = exchange.getClass().getMethod("getConnection").invoke(exchange);
            connection.getClass().getMethod("close").invoke(connection);
            return true;
        } catch (ReflectiveOperationException | RuntimeException ex) {
            return false;
        }
    }
}
