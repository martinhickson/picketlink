package org.picketlink.oidc.provider;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Browser SSO session at the authorization endpoint. One sid is shared by every client
 * that signs in through this browser until logout or a different subject signs in.
 */
final class SsoSession {

    static final String SUBJECT = "org.picketlink.oidc.sso.subject";
    static final String SID = "org.picketlink.oidc.sso.sid";
    static final String AUTH_TIME = "org.picketlink.oidc.sso.authTime";
    static final String CLIENTS = "org.picketlink.oidc.sso.clients";

    private SsoSession() {
    }

    /** Records an interactive login. A missing container session still returns a sid. */
    static String login(HttpSession session, String subject, long authTime) {
        if (session == null) {
            return UUID.randomUUID().toString();
        }
        Object current = session.getAttribute(SUBJECT);
        Object sid = session.getAttribute(SID);
        if (!(sid instanceof String) || ((String) sid).isBlank()
                || (current instanceof String && !current.equals(subject))) {
            sid = UUID.randomUUID().toString();
            session.setAttribute(SID, sid);
            session.removeAttribute(CLIENTS);
        }
        session.setAttribute(SUBJECT, subject);
        session.setAttribute(AUTH_TIME, Long.valueOf(authTime));
        return (String) sid;
    }

    /** Remembers a client that received a code in this browser session. */
    static void remember(HttpSession session, String clientId) {
        if (session == null || clientId == null || clientId.isBlank()) {
            return;
        }
        LinkedHashSet<String> clients = new LinkedHashSet<>(clientIds(session));
        if (clients.add(clientId)) {
            session.setAttribute(CLIENTS, clients);
        }
    }

    static Set<String> clientIds(HttpSession session) {
        if (session == null) {
            return Set.of();
        }
        Object value = session.getAttribute(CLIENTS);
        if (!(value instanceof Set)) {
            return Set.of();
        }
        LinkedHashSet<String> clients = new LinkedHashSet<>();
        for (Object item : (Set<?>) value) {
            if (item instanceof String && !((String) item).isBlank()) {
                clients.add((String) item);
            }
        }
        return Collections.unmodifiableSet(clients);
    }

    /** Rotates the container session id after a password login. */
    static void rotate(HttpServletRequest request) {
        if (request == null || request.getSession(false) == null) {
            return;
        }
        try {
            request.changeSessionId();
        } catch (IllegalStateException ex) {
            // the session was already invalidated
        }
    }

    static Held read(HttpSession session) {
        if (session == null) {
            return null;
        }
        Object subject = session.getAttribute(SUBJECT);
        Object sid = session.getAttribute(SID);
        Object authTime = session.getAttribute(AUTH_TIME);
        if (!(subject instanceof String) || ((String) subject).isBlank()
                || !(sid instanceof String) || ((String) sid).isBlank()
                || !(authTime instanceof Long)) {
            return null;
        }
        return new Held((String) subject, (String) sid, ((Long) authTime).longValue());
    }

    /**
     * True when this session may satisfy the request without a new login. {@code max_age}
     * of 0 is never fresh, matching the token endpoint's {@code >=} comparison.
     */
    static boolean fresh(Held held, Long maxAge, long now) {
        if (held == null) {
            return false;
        }
        if (maxAge == null) {
            return true;
        }
        return now - held.authTime < maxAge.longValue();
    }

    static final class Held {
        final String subject;
        final String sid;
        final long authTime;

        Held(String subject, String sid, long authTime) {
            this.subject = subject;
            this.sid = sid;
            this.authTime = authTime;
        }
    }
}
