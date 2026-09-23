# PicketLink Admin — embeddable JWT issuance management UI

`<picketlink-admin>` is an Angular Elements **web component** that manages the PicketLink JWT
issuance layer: REST clients, issuance policies, signing keys and issued tokens. It embeds
into any corporate Angular, React or plain JavaScript site with a single script tag.

## Embedding

```html
<script src="/auth-admin/main.js"></script>

<!-- host owns login: pass a bearer token with the auth-admin scope -->
<picketlink-admin api-base="https://auth.corp.example/api/auth/admin"
                  token="eyJhbGciOiJSUzI..."></picketlink-admin>

<!-- or let the element fetch its own token (client_credentials) -->
<picketlink-admin token-endpoint="https://auth.corp.example/oauth/token"
                  client-id="auth-admin"
                  client-secret="..."></picketlink-admin>
```

With no attributes, `api-base` defaults to the relative `../api/auth/admin` so same-origin
deployments work with zero configuration.

### Route management (why hash routing)

Internal routing uses **HashLocationStrategy** (`#/clients`, `#/policies`, `#/keys`,
`#/tokens`). The element never touches `window.location.pathname`, so:

- it cannot collide with the host application's router (any router, any framework),
- deep links work without server-side rewrite rules,
- multiple instances can coexist on one page.

Verified by `element-smoke.mjs` (run `node element-smoke.mjs` after `npm run build`).

## Building

Part of the `picketlink-auth` Maven build (`frontend-maven-plugin`); output lands in
`META-INF/resources/auth-admin` inside the JAR. Standalone:

```bash
npm install && npm run build && npm test   # element-smoke.mjs runs in the Maven build too
```

## Demo / manual GUI verification

`npm run demo` serves the built element plus a fixture admin API and token endpoint on
<http://localhost:8901> — the element's default relative `api-base` works unchanged, and all
four screens (clients, policies, keys, tokens) render live fixture data. Use it for manual
verification or as the target of browser automation.

## Browser automation

```bash
npm run demo &          # fixture stack on localhost:8901 (no external network)
npm run test:browser    # drives system Chromium headless (playwright-core)
```

17 checks: every screen renders live fixture data, secrets are never displayed, the active
signing key is marked, tokens are shown as hashes only, and hash routing never touches the
host path. Screenshots land in `/tmp/picketlink-admin-{clients,policies,keys,tokens}.png`.
Set `PICKETLINK_CHROMIUM` to use a different browser binary; wrap in `xvfb-run` for headed
runs. Not part of the default Maven build (needs a local Chromium); the jsdom smoke suite
(`npm test`, wired into `generate-resources`) is the always-on gate.

## Backend wiring

Servlet deployment (Tomcat/WildFly, no CXF) — `web.xml`:

```xml
<listener>
  <listener-class>org.picketlink.auth.oauth.servlet.ManagedAuthServerServletContextListener</listener-class>
</listener>

<servlet>
  <servlet-name>OAuthTokenEndpoint</servlet-name>
  <servlet-class>org.picketlink.auth.oauth.servlet.OAuthTokenEndpointServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>OAuthTokenEndpoint</servlet-name>
  <url-pattern>/oauth/token</url-pattern>
</servlet-mapping>

<servlet>
  <servlet-name>AdminApi</servlet-name>
  <servlet-class>org.picketlink.auth.oauth.servlet.AdminApiServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>AdminApi</servlet-name>
  <url-pattern>/api/auth/admin/*</url-pattern>
</servlet-mapping>

<servlet>
  <servlet-name>Jwks</servlet-name>
  <servlet-class>org.picketlink.auth.oauth.servlet.JwksServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>Jwks</servlet-name>
  <url-pattern>/jwks.json</url-pattern>
</servlet-mapping>

<servlet>
  <servlet-name>AdminUi</servlet-name>
  <servlet-class>org.picketlink.auth.oauth.servlet.VirtualResourcesServlet</servlet-class>
  <init-param><param-name>resourceBase</param-name><param-value>META-INF/resources/auth-admin</param-value></init-param>
  <init-param><param-name>urlBase</param-name><param-value>/auth-admin</param-value></init-param>
  <init-param><param-name>adminUiEnabled</param-name><param-value>true</param-value></init-param>
</servlet>
<servlet-mapping>
  <servlet-name>AdminUi</servlet-name>
  <url-pattern>/auth-admin/*</url-pattern>
</servlet-mapping>
```

CXF/JAX-RS deployment: `ManagedIssuanceBootstrap.mount(bus, server)` registers the admin
resources, the `AdminScopeFilter` guard and the JWKS endpoint.

## Storage

Clients, policies and signing-key metadata are stored as JSON documents — in a database
**CLOB** when `picketlink.auth.store=jdbc` (dialect matrix: SQLite, PostgreSQL; Oracle
supported at dialect level, verification deferred), or in-memory otherwise. Token records
(hashed, never raw JWTs) live in `picketlink_auth_tokens` so revocation survives restarts.
**H2 is banned** in this repository — see `picketlink/CLAUDE.md`.

Bootstrap: on first start an `auth-admin` client is seeded with the `auth-admin` scope and a
secret from `PICKETLINK_ADMIN_CLIENT_SECRET` (generated once if unset; the value is not logged). Mint an
admin token via `POST /oauth/token` with `grant_type=client_credentials`.
