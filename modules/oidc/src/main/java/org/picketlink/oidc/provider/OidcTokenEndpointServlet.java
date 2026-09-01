package org.picketlink.oidc.provider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.picketlink.auth.oauth.OAuthConstants;
import org.picketlink.auth.oauth.OAuthException;
import org.picketlink.auth.oauth.auth.ClientAuthentication;
import org.picketlink.auth.oauth.auth.ClientCredentialsAuthenticator;
import org.picketlink.auth.oauth.client.ConstantTimeClientSecretMatcher;
import org.picketlink.auth.oauth.client.store.PersistingClientRegistry;
import org.picketlink.auth.oauth.http.FormParameters;
import org.picketlink.auth.oauth.issuance.IssuanceRequest;
import org.picketlink.auth.oauth.issuance.IssuedToken;
import org.picketlink.auth.oauth.json.OAuthJsonWriter;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.RegisteredClient;
import org.picketlink.auth.oauth.model.TokenRequest;
import org.picketlink.auth.oauth.service.ScopeValidator;

/**
 * OIDC token endpoint ({@code /token}): {@code authorization_code} (PKCE-verified),
 * {@code refresh_token} (rotation + reuse detection) and {@code client_credentials}. Access
 * and ID tokens are JWTs minted through the {@code JwtIssuanceManager} chokepoint, so the
 * issuance policy engine, audit log and revocation registry all apply.
 */
public class OidcTokenEndpointServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private transient OidcProviderServer server;
    private transient ClientCredentialsAuthenticator authenticator;

    public OidcTokenEndpointServlet() {
    }

    public OidcTokenEndpointServlet(OidcProviderServer server) {
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
        String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> form = FormParameters.parse(body);
        TokenRequest tokenRequest = TokenRequest.builder()
                .grantType(form.get(OAuthConstants.GRANT_TYPE))
                .scope(form.get(OAuthConstants.SCOPE))
                .authorizationHeader(request.getHeader("Authorization"))
                .formParameters(form)
                .build();
        try {
            String json = handle(tokenRequest, form);
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(OAuthConstants.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setHeader("Cache-Control", "no-store");
            response.getWriter().write(json);
        } catch (OAuthException ex) {
            response.setStatus(ex.getHttpStatus());
            response.setContentType(OAuthConstants.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(OAuthJsonWriter.writeErrorResponse(ex.getError()));
        }
    }

    private String handle(TokenRequest request, Map<String, String> form) {
        String grantType = request.getGrantType();
        if ("authorization_code".equals(grantType)) {
            return authorizationCode(request, form);
        }
        if ("refresh_token".equals(grantType)) {
            return refreshToken(request, form);
        }
        if (OAuthConstants.CLIENT_CREDENTIALS_GRANT.equals(grantType)) {
            return clientCredentials(request);
        }
        throw oauthError(OAuthConstants.UNSUPPORTED_GRANT_TYPE, "unsupported grant_type");
    }

    private String authorizationCode(TokenRequest request, Map<String, String> form) {
        ClientAuthentication authentication = authenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();
        String code = form.get("code");
        String redirectUri = form.get("redirect_uri");
        String codeVerifier = form.get("code_verifier");

        Optional<AuthorizationCodeService.PendingCode> pending =
                server.getAuthorizationCodes().consume(code, codeVerifier);
        if (!pending.isPresent()) {
            throw oauthError(OAuthConstants.INVALID_GRANT,
                    "authorization code is invalid, expired or PKCE verification failed");
        }
        AuthorizationCodeService.PendingCode consumed = pending.get();
        if (!client.getClientId().equals(consumed.getClientId())
                || redirectUri == null || !redirectUri.equals(consumed.getRedirectUri())) {
            throw oauthError(OAuthConstants.INVALID_GRANT, "code was not issued to this client");
        }
        return issueTokens(client, consumed.getSubject(), parseScopes(consumed.getScopes()),
                consumed.getNonce(), consumed.getAuthTime());
    }

    private String refreshToken(TokenRequest request, Map<String, String> form) {
        ClientAuthentication authentication = authenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();
        String token = form.get("refresh_token");

        Optional<RefreshTokenService.Rotation> rotation = server.getRefreshTokens().rotate(token);
        if (!rotation.isPresent()) {
            throw oauthError(OAuthConstants.INVALID_GRANT,
                    "refresh token is invalid, expired or was replayed");
        }
        RefreshTokenService.Rotation rotated = rotation.get();
        if (!client.getClientId().equals(rotated.getClientId())) {
            throw oauthError(OAuthConstants.INVALID_GRANT, "refresh token was not issued to this client");
        }
        Set<String> scopes = parseScopes(rotated.getScopes());
        IssuedToken access = issueAccess(client, rotated.getSubject(), scopes);
        return tokenResponse(access, rotated.getNewRefreshToken(), scopes);
    }

    private String clientCredentials(TokenRequest request) {
        ClientAuthentication authentication = authenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();
        Set<String> scopes = ScopeValidator.resolveApprovedScopes(client, request.getScope());
        IssuedToken issued = server.getIssuanceServer().getIssuanceManager()
                .issue(IssuanceRequest.forClient(client)
                        .grantType(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
                        .scopes(scopes)
                        .build());
        return tokenResponse(issued, null, scopes);
    }

    private String issueTokens(RegisteredClient client, String subject, Set<String> scopes,
            String nonce, long authTime) {
        IssuedToken access = issueAccess(client, subject, scopes);
        // interop claims most client libraries verify: auth_time and at_hash (RFC 9126 /
        // OIDC Core 3.1.3.6 — left half of the access-token hash, SHA-256 for our alg family)
        java.util.Map<String, String> idTokenClaims = new java.util.LinkedHashMap<>(
                server.getClaimSource().claimsFor(subject));
        idTokenClaims.put("auth_time", String.valueOf(authTime));
        idTokenClaims.put("at_hash", atHash(access.getTokenValue()));
        // ID token: same signing chokepoint, subject + nonce, audience is the client
        IssuedToken idToken = server.getIssuanceServer().getIssuanceManager()
                .issue(IssuanceRequest.forClient(client)
                        .grantType("oidc-id-token")
                        .scopes(new LinkedHashSet<>())
                        .subject(subject)
                        .nonce(nonce)
                        .extraClaims(idTokenClaims)
                        .requestedLifetimeSeconds(3600L)
                        .build());
        StringBuilder json = new StringBuilder("{");
        json.append("\"access_token\":\"").append(OAuthJsonWriter.escape(access.getTokenValue())).append('"');
        json.append(",\"token_type\":\"").append(OAuthConstants.BEARER_TOKEN_TYPE).append('"');
        json.append(",\"expires_in\":").append(access.getLifetimeSeconds());
        json.append(",\"id_token\":\"").append(OAuthJsonWriter.escape(idToken.getTokenValue())).append('"');
        if (!scopes.isEmpty()) {
            json.append(",\"scope\":\"").append(OAuthJsonWriter.escape(ScopeValidator.formatScope(scopes)))
                    .append('"');
        }
        String refreshToken = server.getRefreshTokens()
                .create(client.getClientId(), subject, ScopeValidator.formatScope(scopes), nonce);
        json.append(",\"refresh_token\":\"").append(OAuthJsonWriter.escape(refreshToken)).append('"');
        json.append('}');
        return json.toString();
    }

    /** Base64url of the leftmost 128 bits of SHA-256 over the access token. */
    private static String atHash(String accessToken) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.UTF_8));
            byte[] leftHalf = new byte[16];
            System.arraycopy(digest, 0, leftHalf, 0, 16);
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(leftHalf);
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private IssuedToken issueAccess(RegisteredClient client, String subject, Set<String> scopes) {
        return server.getIssuanceServer().getIssuanceManager()
                .issue(IssuanceRequest.forClient(client)
                        .grantType("authorization_code")
                        .scopes(scopes)
                        .subject(subject)
                        .build());
    }

    private String tokenResponse(IssuedToken issued, String refreshToken, Set<String> scopes) {
        StringBuilder json = new StringBuilder("{");
        json.append("\"access_token\":\"").append(OAuthJsonWriter.escape(issued.getTokenValue())).append('"');
        json.append(",\"token_type\":\"").append(OAuthConstants.BEARER_TOKEN_TYPE).append('"');
        json.append(",\"expires_in\":").append(issued.getLifetimeSeconds());
        if (refreshToken != null) {
            json.append(",\"refresh_token\":\"").append(OAuthJsonWriter.escape(refreshToken)).append('"');
        }
        if (!scopes.isEmpty()) {
            json.append(",\"scope\":\"").append(OAuthJsonWriter.escape(ScopeValidator.formatScope(scopes)))
                    .append('"');
        }
        json.append('}');
        return json.toString();
    }

    private static Set<String> parseScopes(String scopes) {
        Set<String> values = new LinkedHashSet<>();
        if (scopes != null && !scopes.isBlank()) {
            values.addAll(Arrays.asList(scopes.trim().split("\\s+")));
        }
        return values;
    }

    private static OAuthException oauthError(String error, String description) {
        return new OAuthException(new OAuthErrorResponse(error, description), 400);
    }
}
