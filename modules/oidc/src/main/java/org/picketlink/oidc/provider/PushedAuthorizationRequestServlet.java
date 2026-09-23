package org.picketlink.oidc.provider;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.auth.ClientAuthentication;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.store.PersistingClientRegistry;
import org.picketlink.auth.oauth.http.FormParameters;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;

/**
 * PAR push endpoint (RFC 9126, typically mapped at {@code /par}): an authenticated client
 * POSTs its authorization parameters and receives a one-time {@code request_uri} plus
 * {@code expires_in}. Parameters are validated exactly as the authorization endpoint would
 * (registered redirect URI, response_type=code, PKCE S256), so nothing invalid can be
 * pushed and nothing pushed can be tampered with.
 */
public class PushedAuthorizationRequestServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient OidcProviderServer server;
    private transient ClientCredentialsAuthenticator authenticator;

    public PushedAuthorizationRequestServlet() {
    }

    public PushedAuthorizationRequestServlet(OidcProviderServer server) {
        this.server = server;
        if (server != null) {
            this.authenticator = newAuthenticator(server);
        }
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
        authenticator = newAuthenticator(server);
    }

    private static ClientCredentialsAuthenticator newAuthenticator(OidcProviderServer server) {
        return new ClientCredentialsAuthenticator(
                new PersistingClientRegistry(server.getIssuanceServer().getClientStore()),
                new ConstantTimeClientSecretMatcher());
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try (InputStream in = request.getInputStream()) {
            Map<String, String> form = FormParameters.parse(
                    new String(in.readAllBytes(), StandardCharsets.UTF_8));
            TokenRequest tokenRequest = TokenRequest.builder()
                    .grantType(form.get(OAuthConstants.GRANT_TYPE))
                    .scope(form.get(OAuthConstants.SCOPE))
                    .authorizationHeader(request.getHeader("Authorization"))
                    .formParameters(form)
                    .build();
            ClientAuthentication authentication = authenticator.authenticate(tokenRequest);
            RegisteredClient client = authentication.getClient();

            String redirectUri = form.get("redirect_uri");
            if (redirectUri == null || !client.getAllowedRedirectUris().contains(redirectUri)) {
                writeError(response, 400, "invalid redirect_uri");
                return;
            }
            if (!"code".equals(form.get("response_type"))) {
                writeError(response, 400, "unsupported_response_type");
                return;
            }
            String codeChallenge = form.get("code_challenge");
            String codeChallengeMethod = form.get("code_challenge_method");
            if (!AuthorizationCodeService.s256ChallengeAccepted(codeChallenge, codeChallengeMethod)) {
                writeError(response, 400, "PKCE S256 is required");
                return;
            }

            String requestUri = server.getPushedAuthorizationRequests()
                    .push(client.getClientId(), form);
            long expiresIn = server.getPushedAuthorizationRequests().lifetimeSeconds();
            response.setStatus(HttpServletResponse.SC_CREATED);
            response.setContentType(OAuthConstants.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write("{\"request_uri\":\""
                    + OAuthJsonWriter.escape(requestUri) + "\",\"expires_in\":" + expiresIn + "}");
        } catch (org.picketlink.auth.oauth.OAuthException ex) {
            writeError(response, ex.getHttpStatus(), ex.getError().getErrorDescription());
        }
    }

    private static void writeError(HttpServletResponse response, int status, String description)
            throws IOException {
        response.setStatus(status);
        response.setContentType(OAuthConstants.APPLICATION_JSON);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"error\":\""
                + OAuthJsonWriter.escape(OAuthConstants.INVALID_REQUEST) + "\",\"error_description\":\""
                + OAuthJsonWriter.escape(description) + "\"}");
    }
}
