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
import org.picketlink.auth.oauth.servlet.NextTokenPostFault;

/**
 * OIDC token endpoint ({@code /token}): {@code authorization_code} (PKCE-verified),
 * {@code refresh_token} (rotation + reuse detection), {@code password} and
 * {@code client_credentials}. Access and ID tokens are JWTs minted through the
 * {@code JwtIssuanceManager} chokepoint, so the issuance policy engine, audit log and
 * revocation registry all apply.
 */
public class OidcTokenEndpointServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final String TOKEN_EXCHANGE_GRANT =
            "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String DEVICE_CODE_GRANT =
            "urn:ietf:params:oauth:grant-type:device_code";

    private transient OidcProviderServer server;
    private transient ClientCredentialsAuthenticator authenticator;
    private transient DpopProofValidator dpopValidator;
    private transient NextTokenPostFault nextPostFault = new NextTokenPostFault();

    public OidcTokenEndpointServlet() {
    }

    public OidcTokenEndpointServlet(OidcProviderServer server) {
        this(server, new NextTokenPostFault());
    }

    public OidcTokenEndpointServlet(OidcProviderServer server, NextTokenPostFault nextPostFault) {
        this.server = server;
        this.nextPostFault = nextPostFault;
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
        Object fault = getServletContext().getAttribute(NextTokenPostFault.class.getName());
        if (fault instanceof NextTokenPostFault) {
            nextPostFault = (NextTokenPostFault) fault;
        }
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
        if (request.getHeader("DPoP") != null) {
            form.put("DPoP", request.getHeader("DPoP"));
        }
        TokenRequest tokenRequest = TokenRequest.builder()
                .grantType(form.get(OAuthConstants.GRANT_TYPE))
                .scope(form.get(OAuthConstants.SCOPE))
                .authorizationHeader(request.getHeader("Authorization"))
                .formParameters(form)
                .build();
        if (nextPostFault.consume()) {
            response.setHeader("Connection", "close");
            throw new IOException("Connection closed");
        }
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
        if (OAuthConstants.PASSWORD_GRANT.equals(grantType)) {
            return password(request, form);
        }
        if (OAuthConstants.CLIENT_CREDENTIALS_GRANT.equals(grantType)) {
            return clientCredentials(request);
        }
        if (TOKEN_EXCHANGE_GRANT.equals(grantType)) {
            return tokenExchange(request, form);
        }
        if (DEVICE_CODE_GRANT.equals(grantType)) {
            return deviceCode(request, form);
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
                server.getAuthorizationCodes().consume(code, codeVerifier,
                        client.getClientId(), redirectUri);
        if (!pending.isPresent()) {
            throw oauthError(OAuthConstants.INVALID_GRANT,
                    "authorization code is invalid, expired or PKCE verification failed");
        }
        AuthorizationCodeService.PendingCode consumed = pending.get();
        if (!client.getClientId().equals(consumed.getClientId())
                || redirectUri == null || !redirectUri.equals(consumed.getRedirectUri())) {
            throw oauthError(OAuthConstants.INVALID_GRANT, "code was not issued to this client");
        }
        // OIDC Core 3.1.3.7: when max_age was requested, the authentication must still be
        // recent enough — a code exchanged too late fails closed instead of issuing an
        // ID token whose auth_time violates the relying party's freshness requirement
        if (consumed.getMaxAge() != null
                && server.getClock().instant().getEpochSecond()
                        - consumed.getAuthTime() >= consumed.getMaxAge()) {
            throw oauthError(OAuthConstants.INVALID_GRANT, "authentication is older than max_age");
        }
        String presentedJkt = dpopJkt(request);
        if (consumed.getDpopJkt() != null && !consumed.getDpopJkt().equals(presentedJkt)) {
            throw oauthError(OAuthConstants.INVALID_GRANT, "DPoP proof does not match dpop_jkt");
        }
        return issueTokens(client, consumed.getSubject(),
                ScopeValidator.resolveApprovedScopes(client, consumed.getScopes()),
                consumed.getNonce(), consumed.getAuthTime(), consumed.getSid(),
                consumed.getDpopJkt() != null ? consumed.getDpopJkt() : presentedJkt,
                "authorization_code");
    }

    private String password(TokenRequest request, Map<String, String> form) {
        ClientAuthentication authentication = authenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();
        String username = form.get(OAuthConstants.USERNAME);
        String password = form.get(OAuthConstants.PASSWORD);
        if (username == null || username.isBlank() || password == null) {
            throw oauthError(OAuthConstants.INVALID_REQUEST, "username and password are required");
        }
        Optional<String> subject = server.getSubjectAuthenticator().authenticate(username, password);
        if (subject.isEmpty()) {
            throw oauthError(OAuthConstants.INVALID_GRANT, "invalid resource owner credentials");
        }
        Set<String> scopes = ScopeValidator.resolveApprovedScopes(client, request.getScope());
        return issueTokens(client, subject.get(), scopes, form.get("nonce"),
                server.getClock().instant().getEpochSecond(), null, dpopJkt(request),
                OAuthConstants.PASSWORD_GRANT);
    }

    private String refreshToken(TokenRequest request, Map<String, String> form) {
        ClientAuthentication authentication = authenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();
        String token = form.get("refresh_token");

        Optional<RefreshTokenRecord> live = server.getRefreshTokens().findLive(token);
        if (live.isPresent() && !client.getClientId().equals(live.get().getClientId())) {
            throw oauthError(OAuthConstants.INVALID_GRANT, "refresh token was not issued to this client");
        }
        String scopesForRotation = null;
        if (live.isPresent()) {
            String requested = form.get("scope");
            if (requested != null && !requested.isBlank()) {
                Set<String> granted = parseScopes(live.get().getScopes());
                Set<String> asked = parseScopes(requested);
                if (!granted.containsAll(asked)) {
                    throw oauthError(OAuthConstants.INVALID_SCOPE,
                            "requested scope exceeds the granted scope");
                }
                scopesForRotation = ScopeValidator.formatScope(asked);
            }
        }
        String presentedJkt = null;
        if (live.isPresent() && live.get().getDpopJkt() != null) {
            presentedJkt = dpopJkt(request);
            if (presentedJkt == null || !live.get().getDpopJkt().equals(presentedJkt)) {
                throw oauthError(OAuthConstants.INVALID_GRANT,
                        "DPoP proof is required for this refresh token");
            }
        } else if (dpopHeader(request) != null) {
            presentedJkt = dpopJkt(request);
        }
        Optional<RefreshTokenService.Rotation> rotation =
                server.getRefreshTokens().rotate(token, client.getClientId(), scopesForRotation,
                        presentedJkt);
        if (!rotation.isPresent()) {
            throw oauthError(OAuthConstants.INVALID_GRANT,
                    "refresh token is invalid, expired or was replayed");
        }
        RefreshTokenService.Rotation rotated = rotation.get();
        Set<String> scopes = parseScopes(rotated.getScopes());
        IssuedToken access = issueAccess(client, rotated.getSubject(), scopes,
                rotated.getDpopJkt(), "refresh_token");
        return tokenResponse(access, rotated.getNewRefreshToken(), scopes);
    }

    /** RFC 8628 device polling: pending grants answer authorization_pending, approved ones issue tokens. */
    private String deviceCode(TokenRequest request, Map<String, String> form) {
        ClientAuthentication authentication = authenticator.authenticate(request);
        String deviceCode = form.get("device_code");
        if (deviceCode == null || deviceCode.isBlank()) {
            throw oauthError(OAuthConstants.INVALID_REQUEST, "device_code is required");
        }
        java.util.Optional<DeviceAuthorizationService.DeviceGrant> grant =
                server.getDeviceAuthorizations().poll(deviceCode,
                        authentication.getClient().getClientId());
        if (grant.isEmpty()) {
            throw oauthError(OAuthConstants.INVALID_GRANT,
                    DeviceAuthorizationService.ERROR_EXPIRED_TOKEN);
        }
        DeviceAuthorizationService.DeviceGrant state = grant.get();
        if (state.isSlowDown()) {
            throw oauthError(DeviceAuthorizationService.ERROR_SLOW_DOWN,
                    "the client must increase its polling interval");
        }
        if (state.getStatus() == DeviceAuthorizationService.Status.DENIED) {
            throw oauthError(OAuthConstants.INVALID_GRANT,
                    DeviceAuthorizationService.ERROR_ACCESS_DENIED);
        }
        if (state.getStatus() != DeviceAuthorizationService.Status.CONSUMED
                && state.getSubject() == null) {
            throw oauthError(DeviceAuthorizationService.ERROR_AUTHORIZATION_PENDING,
                    "the authorization request is still pending");
        }
        Set<String> scopes = ScopeValidator.resolveApprovedScopes(
                authentication.getClient(), state.getScopes());
        String dpopJkt = dpopJkt(request);
        RegisteredClient client = authentication.getClient();
        IssuedToken access = issueAccess(client, state.getSubject(), scopes, dpopJkt,
                DEVICE_CODE_GRANT);
        StringBuilder json = new StringBuilder("{");
        json.append("\"access_token\":\"").append(org.picketlink.auth.oauth.json.OAuthJsonWriter
                .escape(access.getTokenValue())).append('"');
        json.append(",\"token_type\":\"").append(tokenType(dpopJkt)).append('"');
        json.append(",\"expires_in\":").append(access.getLifetimeSeconds());
        if (scopes.contains("openid")) {
            json.append(",\"id_token\":\"").append(OAuthJsonWriter.escape(
                    idToken(client, state.getSubject(), scopes, null, state.getAuthTime(),
                            access, null).getTokenValue()))
                    .append('"');
        }
        if (!scopes.isEmpty()) {
            json.append(",\"scope\":\"").append(
                    org.picketlink.auth.oauth.json.OAuthJsonWriter.escape(
                            org.picketlink.auth.oauth.service.ScopeValidator.formatScope(scopes)))
                    .append('"');
        }
        String refreshToken = server.getRefreshTokens().create(client.getClientId(),
                state.getSubject(), ScopeValidator.formatScope(scopes), null, dpopJkt);
        json.append(",\"refresh_token\":\"").append(OAuthJsonWriter.escape(refreshToken)).append('"');
        json.append('}');
        return json.toString();
    }

    /**
     * Token Exchange (RFC 8693): an authenticated client exchanges a valid subject token
     * (our JWT access token) for a new one scoped to a requested audience — the
     * microservice delegation pattern. The subject carries over; when an actor_token is
     * supplied it is validated too and recorded as the delegation actor ({@code act}
     * chain), so the original caller stays auditable down the chain.
     */
    private String tokenExchange(TokenRequest request, Map<String, String> form) {
        ClientAuthentication authentication = authenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();

        String subjectToken = form.get("subject_token");
        String subjectTokenType = form.get("subject_token_type");
        if (subjectToken == null || subjectToken.isBlank()) {
            throw oauthError(OAuthConstants.INVALID_REQUEST, "subject_token is required");
        }
        if (subjectTokenType != null
                && !"urn:ietf:params:oauth:token-type:jwt".equals(subjectTokenType)
                && !"urn:ietf:params:oauth:token-type:access_token".equals(subjectTokenType)) {
            throw oauthError(OAuthConstants.INVALID_REQUEST, "unsupported subject_token_type");
        }

        org.apache.cxf.rs.security.jose.jwt.JwtClaims subjectClaims;
        try {
            subjectClaims = server.getIssuanceServer().getIssuanceManager().validate(subjectToken);
        } catch (RuntimeException ex) {
            throw oauthError(OAuthConstants.INVALID_GRANT, "subject_token is invalid: "
                    + ex.getMessage());
        }

        // optional delegation actor (RFC 8693 section 4.4): recorded as act.sub
        java.util.Map<String, Object> extra = new java.util.LinkedHashMap<>();
        String actorToken = form.get("actor_token");
        if (actorToken != null && !actorToken.isBlank()) {
            try {
                org.apache.cxf.rs.security.jose.jwt.JwtClaims actorClaims =
                        server.getIssuanceServer().getIssuanceManager().validate(actorToken);
                // preserve an existing chain, then append the new actor
                Object existingAct = subjectClaims.getClaim("act");
                java.util.Map<String, Object> act = new java.util.LinkedHashMap<>();
                if (existingAct instanceof java.util.Map) {
                    act.put("act", existingAct);
                }
                act.put("sub", actorClaims.getSubject());
                extra.put("act", act);
            } catch (RuntimeException ex) {
                throw oauthError(OAuthConstants.INVALID_GRANT,
                        "actor_token is invalid: " + ex.getMessage());
            }
        }

        Set<String> audiences = new LinkedHashSet<>();
        String requestedAudience = form.get("audience");
        if (requestedAudience != null && !requestedAudience.isBlank()) {
            audiences.addAll(Arrays.asList(requestedAudience.trim().split("\s+")));
        }
        Set<String> scopes = parseScopes(subjectClaims.getClaim(
                org.picketlink.auth.oauth.issuance.JwtIssuanceManager.CLAIM_SCOPE) == null
                        ? null
                        : String.valueOf(subjectClaims.getClaim(
                                org.picketlink.auth.oauth.issuance.JwtIssuanceManager.CLAIM_SCOPE)));

        String dpopJkt = dpopJkt(request);
        if (dpopJkt != null) {
            java.util.Map<String, Object> cnf = new java.util.LinkedHashMap<>();
            cnf.put("jkt", dpopJkt);
            extra.put("cnf", cnf);
        }

        IssuedToken exchanged = server.getIssuanceServer().getIssuanceManager()
                .issue(IssuanceRequest.forClient(client)
                        .grantType(TOKEN_EXCHANGE_GRANT)
                        .scopes(scopes)
                        .subject(subjectClaims.getSubject())
                        .audiences(audiences)
                        .extraClaims(extra)
                        .build());
        StringBuilder json = new StringBuilder("{");
        json.append("\"access_token\":\"").append(org.picketlink.auth.oauth.json.OAuthJsonWriter
                .escape(exchanged.getTokenValue())).append('"');
        json.append(",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:jwt\"");
        json.append(",\"token_type\":\"").append(tokenType(dpopJkt)).append('"');
        json.append(",\"expires_in\":").append(exchanged.getLifetimeSeconds());
        if (!scopes.isEmpty()) {
            json.append(",\"scope\":\"").append(
                    org.picketlink.auth.oauth.json.OAuthJsonWriter.escape(
                            org.picketlink.auth.oauth.service.ScopeValidator.formatScope(scopes)))
                    .append('"');
        }
        json.append('}');
        return json.toString();
    }

    private String clientCredentials(TokenRequest request) {
        ClientAuthentication authentication = authenticator.authenticate(request);
        RegisteredClient client = authentication.getClient();
        Set<String> scopes = ScopeValidator.resolveApprovedScopes(client, request.getScope());
        IssuedToken issued = issueAccess(client, client.getClientId(), scopes, dpopJkt(request),
                OAuthConstants.CLIENT_CREDENTIALS_GRANT);
        return tokenResponse(issued, null, scopes);
    }

    private String issueTokens(RegisteredClient client, String subject, Set<String> scopes,
            String nonce, long authTime, String sid, String dpopJkt, String grantType) {
        IssuedToken access = issueAccess(client, subject, scopes, dpopJkt, grantType);
        StringBuilder json = new StringBuilder("{");
        json.append("\"access_token\":\"").append(OAuthJsonWriter.escape(access.getTokenValue())).append('"');
        json.append(",\"token_type\":\"").append(tokenType(dpopJkt)).append('"');
        json.append(",\"expires_in\":").append(access.getLifetimeSeconds());
        if (scopes.contains("openid")) {
            json.append(",\"id_token\":\"").append(OAuthJsonWriter.escape(
                    idToken(client, subject, scopes, nonce, authTime, access, sid).getTokenValue()))
                    .append('"');
        }
        if (!scopes.isEmpty()) {
            json.append(",\"scope\":\"").append(OAuthJsonWriter.escape(ScopeValidator.formatScope(scopes)))
                    .append('"');
        }
        String refreshToken = server.getRefreshTokens()
                .create(client.getClientId(), subject, ScopeValidator.formatScope(scopes), nonce,
                        dpopJkt);
        json.append(",\"refresh_token\":\"").append(OAuthJsonWriter.escape(refreshToken)).append('"');
        json.append('}');
        return json.toString();
    }

    /** OIDC ID token. Issued only when the approved scope includes {@code openid}. */
    private IssuedToken idToken(RegisteredClient client, String subject, Set<String> scopes,
            String nonce, long authTime, IssuedToken access, String sid) {
        // OIDC Core 3.1.3.6 — left half of the access-token hash, SHA-256 for our alg family
        java.util.Map<String, Object> idTokenClaims = new java.util.LinkedHashMap<>(
                ScopedClaims.select(scopes, server.getClaimSource().claimsFor(subject)));
        idTokenClaims.put("auth_time", Long.valueOf(authTime));
        idTokenClaims.put("at_hash", atHash(access.getTokenValue()));
        idTokenClaims.put("sid", sid == null || sid.isBlank()
                ? java.util.UUID.randomUUID().toString() : sid);
        // ID token: same signing chokepoint, subject + nonce, audience is the client
        IssuedToken idToken = server.getIssuanceServer().getIssuanceManager()
                .issue(IssuanceRequest.forClient(client)
                        .grantType("oidc-id-token")
                        .scopes(new LinkedHashSet<>())
                        .audiences(java.util.Set.of(client.getClientId()))
                        .subject(subject)
                        .nonce(nonce)
                        .extraClaims(idTokenClaims)
                        .requestedLifetimeSeconds(3600L)
                        .build());
        return idToken;
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

    private IssuedToken issueAccess(RegisteredClient client, String subject, Set<String> scopes,
            String dpopJkt, String grantType) {
        java.util.Map<String, Object> extra = null;
        if (dpopJkt != null) {
            // RFC 9449: proof-of-possession binding — the token is only usable with the
            // client's key whose thumbprint matches
            java.util.Map<String, Object> cnf = new java.util.LinkedHashMap<>();
            cnf.put("jkt", dpopJkt);
            extra = new java.util.LinkedHashMap<>();
            extra.put("cnf", cnf);
        }
        return server.getIssuanceServer().getIssuanceManager()
                .issue(IssuanceRequest.forClient(client)
                        .grantType(grantType)
                        .scopes(scopes)
                        .subject(subject)
                        .extraClaims(extra)
                        .build());
    }

    /**
     * DPoP (RFC 9449): when the request carries a DPoP proof header, validate it against
     * this request (method + URI) and return the thumbprint to bind into the access token.
     */
    private String dpopJkt(TokenRequest request) {
        String proof = dpopHeader(request);
        if (proof == null) {
            return null;
        }
        if (dpopValidator == null) {
            dpopValidator = new DpopProofValidator(server.getClock());
        }
        try {
            return dpopValidator.validate(proof, "POST", tokenEndpointUri(request));
        } catch (DpopProofValidator.DpopValidationException ex) {
            throw oauthError(OAuthConstants.INVALID_CLIENT, "invalid DPoP proof: " + ex.getMessage());
        }
    }

    private String tokenEndpointUri(TokenRequest request) {
        // the htu the proof binds to; deployments behind a proxy can force it via property
        String configured = System.getProperty("picketlink.oidc.token.endpoint.uri");
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        return server.endpoint("/token");
    }

    private static String dpopHeader(TokenRequest request) {
        // DPoP arrives as an HTTP header; TokenRequest carries form params, so the endpoint
        // servlet forwards it through the form-parameters map under a reserved key
        return request.getFormParameter("DPoP");
    }

    private String tokenResponse(IssuedToken issued, String refreshToken, Set<String> scopes) {
        StringBuilder json = new StringBuilder("{");
        json.append("\"access_token\":\"").append(OAuthJsonWriter.escape(issued.getTokenValue())).append('"');
        json.append(",\"token_type\":\"").append(tokenType(issued)).append('"');
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

    /** RFC 9449: a proof-bound access token is type {@code DPoP}, otherwise {@code Bearer}. */
    private static String tokenType(String dpopJkt) {
        return dpopJkt == null ? OAuthConstants.BEARER_TOKEN_TYPE : "DPoP";
    }

    private static String tokenType(IssuedToken issued) {
        return issued.getClaims() != null && issued.getClaims().getClaim("cnf") != null
                ? "DPoP" : OAuthConstants.BEARER_TOKEN_TYPE;
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
