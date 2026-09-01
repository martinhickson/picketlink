# PicketLink OIDC Provider — deployment

The production provider (`org.picketlink.oidc.provider`) is a set of plain servlets built on
the managed JWT issuance core — deployable on Tomcat or WildFly without CXF.

## web.xml

```xml
<listener>
  <listener-class>org.picketlink.oidc.provider.OidcProviderServletContextListener</listener-class>
</listener>

<context-param>
  <param-name>issuer</param-name>
  <param-value>https://auth.corp.example</param-value>
</context-param>
<!-- optional: class implementing org.picketlink.oidc.provider.SubjectAuthenticator
     (no-arg constructor). Default denies all logins. PicketLink IDM-backed example:

     new IdmSubjectAuthenticator(partitionManager.createIdentityManager(realm))

     verifies passwords through IDM's credential pipeline and enriches ID tokens /
     UserInfo with standard OIDC profile claims (email, name, given_name, family_name,
     preferred_username) from the IDM user. Wire it via a custom authenticator class with a
     no-arg constructor (or extend the listener). -->
<!--
<context-param>
  <param-name>subjectAuthenticator</param-name>
  <param-value>com.corp.auth.CorporateSubjectAuthenticator</param-value>
</context-param>
-->

<servlet>
  <servlet-name>Authorize</servlet-name>
  <servlet-class>org.picketlink.oidc.provider.AuthorizationEndpointServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>Authorize</servlet-name>
  <url-pattern>/authorize</url-pattern>
</servlet-mapping>

<servlet>
  <servlet-name>Token</servlet-name>
  <servlet-class>org.picketlink.oidc.provider.OidcTokenEndpointServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>Token</servlet-name>
  <url-pattern>/token</url-pattern>
</servlet-mapping>

<servlet>
  <servlet-name>Userinfo</servlet-name>
  <servlet-class>org.picketlink.oidc.provider.UserInfoServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>Userinfo</servlet-name>
  <url-pattern>/userinfo</url-pattern>
</servlet-mapping>

<servlet>
  <servlet-name>Logout</servlet-name>
  <servlet-class>org.picketlink.oidc.provider.LogoutEndpointServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>Logout</servlet-name>
  <url-pattern>/logout</url-pattern>
</servlet-mapping>

<servlet>
  <servlet-name>Discovery</servlet-name>
  <servlet-class>org.picketlink.oidc.provider.DiscoveryServlet</servlet-class>
  <init-param>
    <param-name>basePath</param-name>
    <param-value></param-value> <!-- adjust when mounted under a sub-path -->
  </init-param>
</servlet>
<servlet-mapping>
  <servlet-name>Discovery</servlet-name>
  <url-pattern>/.well-known/openid-configuration</url-pattern>
</servlet-mapping>

<servlet>
  <servlet-name>Jwks</servlet-name>
  <servlet-class>org.picketlink.auth.oauth.servlet.JwksServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>Jwks</servlet-name>
  <url-pattern>/jwks.json</url-pattern>
</servlet-mapping>
```

For the admin API and admin UI, additionally mount
`org.picketlink.auth.oauth.servlet.AdminApiServlet` at `/api/auth/admin/*` and the
`VirtualResourcesServlet` at `/auth-admin/*` — see `modules/auth/picketlink-admin/README.md`.

## Configuration

- `issuer` init-param or `picketlink.auth.issuer` / `PICKETLINK_AUTH_ISSUER`
- Storage: `-Dpicketlink.auth.store=jdbc` plus `-Dpicketlink.auth.jdbc.url|user|password`
  (SQLite/PostgreSQL today; see the dialect rules in `picketlink/CLAUDE.md` — H2 banned).
  Without JDBC: in-memory clients, ephemeral signing key, non-persistent token records.
- Signing keys (JDBC profile): `-Dpicketlink.auth.keystore.path` / `...password`
  (PKCS12; auto-generated on first start, rotatable via the admin API).
- Bootstrap admin client: `PICKETLINK_ADMIN_CLIENT_SECRET` (generated + logged once if unset).

## Security properties (verified by tests)

- Authorization codes: single-use, 60s, client+redirect bound, PKCE S256 mandatory
- ID tokens: `at_hash` (OIDC Core 3.1.3.6) and `auth_time` claims, `nonce` echoed,
  OIDC profile claims from IDM (email, name, ...)
- Request objects: signed `request` JWTs verified against the client's registered JWKS
  (iss/sub = client, aud = issuer; parameters take precedence per OIDC Core 6.1);
  unsigned request objects and `request_uri` are rejected (SSRF-safe)
- Refresh tokens: rotation on use, family revocation on replay, JDBC-persistent (hashed)
- Logout: registered post-logout URIs only; no open redirect; Back-Channel Logout 1.0
  for clients with a registered `backchannelLogoutUrl` (signed logout_token POST)
- DPoP (RFC 9449): requests carrying a DPoP proof bind the access token to the proof key's
  RFC 7638 thumbprint (`cnf.jkt`); DPoP-bound tokens are rejected at protected endpoints
  (e.g. UserInfo) without a fresh, matching proof — stolen bearer strings are useless
- prompt=none answers `login_required` per OIDC Core 3.1.2.1 (session-less provider);
  `ProviderCorsFilter` (allow-listed origins, DPoP header aware) enables SPA clients
- All tokens issued through the policy/audit/revocation chokepoint
