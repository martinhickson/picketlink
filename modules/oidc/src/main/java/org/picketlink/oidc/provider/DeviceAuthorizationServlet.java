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
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.service.ScopeValidator;

/**
 * RFC 8628 device authorization endpoint (typically {@code POST /device_authorization}):
 * an authenticated device client requests a grant and receives the {@code device_code},
 * short {@code user_code}, {@code verification_uri}, lifetime and poll interval to show
 * to the user. The verification page itself is {@link DeviceVerificationServlet}.
 */
public class DeviceAuthorizationServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient OidcProviderServer server;
    private transient ClientCredentialsAuthenticator authenticator;

    public DeviceAuthorizationServlet() {
    }

    public DeviceAuthorizationServlet(OidcProviderServer server) {
        this.server = server;
        this.authenticator = newAuthenticator(server);
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
            String scope = ScopeValidator.formatScope(ScopeValidator.resolveApprovedScopes(
                    authentication.getClient(), form.get(OAuthConstants.SCOPE)));

            DeviceAuthorizationService.DeviceGrant grant = server.getDeviceAuthorizations()
                    .create(authentication.getClient().getClientId(), scope == null ? "" : scope);
            String verificationUri = System.getProperty("picketlink.oidc.device.verification.uri",
                    server.getIssuer() + "/device");
            StringBuilder json = new StringBuilder("{");
            json.append("\"device_code\":\"").append(OAuthJsonWriter.escape(grant.getDeviceCode())).append('"');
            json.append(",\"user_code\":\"").append(grant.getUserCode()).append('"');
            json.append(",\"verification_uri\":\"").append(OAuthJsonWriter.escape(verificationUri)).append('"');
            json.append(",\"expires_in\":").append(server.getDeviceAuthorizations().lifetimeSeconds());
            json.append(",\"interval\":").append(server.getDeviceAuthorizations().pollIntervalSeconds());
            json.append('}');
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(OAuthConstants.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(json.toString());
        } catch (org.picketlink.auth.oauth.OAuthException ex) {
            response.setStatus(ex.getHttpStatus());
            response.setContentType(OAuthConstants.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(OAuthJsonWriter.writeErrorResponse(ex.getError()));
        }
    }
}
