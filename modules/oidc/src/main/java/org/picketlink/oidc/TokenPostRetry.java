package org.picketlink.oidc;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class TokenPostRetry {

    private static final Logger LOG = Logger.getLogger(TokenPostRetry.class.getName());

    private TokenPostRetry() {
    }

    public static void once(IoAction action) throws IOException {
        try {
            action.run();
        } catch (IOException | RuntimeException ex) {
            if (!isClosedConnection(ex)) {
                throw ex;
            }
            LOG.log(Level.FINE, "Retrying token POST after a closed connection", ex);
            action.run();
        }
    }

    public static boolean isClosedConnection(Throwable error) {
        Throwable current = error;
        while (current != null) {
            String name = current.getClass().getSimpleName();
            String message = current.getMessage() == null ? "" : current.getMessage();
            if (name.contains("ConnectionClosed")
                    || name.contains("NoHttpResponse")
                    || message.contains("Connection closed")
                    || message.contains("Connection reset")) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    @FunctionalInterface
    public interface IoAction {
        void run() throws IOException;
    }
}
