package org.picketlink.oidc.provider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * RFC 8628 verification page ({@code /device}): the user enters (or is shown, via
 * {@code ?user_code=} deep link) the device's user code, authenticates with the
 * configured {@link SubjectAuthenticator}, and approves or denies the device. Codes are
 * single-decision: PENDING grants only.
 */
public class DeviceVerificationServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient OidcProviderServer server;

    public DeviceVerificationServlet() {
    }

    public DeviceVerificationServlet(OidcProviderServer server) {
        this.server = server;
    }

    @Override
    public void init() {
        if (server == null) {
            Object configured = getServletContext().getAttribute(OidcProviderServer.class.getName());
            if (configured instanceof OidcProviderServer) {
                server = (OidcProviderServer) configured;
            }
        }
        if (server == null) {
            throw new IllegalStateException("OidcProviderServer must be configured");
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String prefill = request.getParameter("user_code");
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/html");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        StringBuilder html = new StringBuilder("<!doctype html><html><body>");
        html.append("<h3>Device activation</h3>");
        html.append("<p>Enter the code shown on your device.</p>");
        html.append("<form method=\"post\">");
        html.append("<label>Code <input name=\"user_code\" value=\"")
                .append(escapeHtml(prefill == null ? "" : prefill)).append("\"/></label> ");
        html.append("<label>Username <input name=\"username\"/></label> ");
        html.append("<label>Password <input name=\"password\" type=\"password\"/></label> ");
        html.append("<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>");
        html.append("<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>");
        html.append("</form></body></html>");
        response.getWriter().write(html.toString());
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userCode = request.getParameter("user_code");
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        boolean approve = "approve".equals(request.getParameter("decision"));

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/html");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        java.util.Optional<String> subject =
                server.getSubjectAuthenticator().authenticate(username, password);
        if (!subject.isPresent()) {
            response.getWriter().write("<p>Invalid credentials</p>");
            return;
        }
        boolean decided = server.getDeviceAuthorizations().decide(userCode, subject.get(), approve);
        response.getWriter().write(decided
                ? "<p>Device " + (approve ? "approved" : "denied") + ". You may return to the device.</p>"
                : "<p>Unknown, expired or already-used code.</p>");
    }

    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }
}
