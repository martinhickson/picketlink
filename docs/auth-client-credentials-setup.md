# OAuth 2.1 Client Credentials and JWT — Setup Guide

This document describes the **PicketLink Auth** module (`picketlink-auth`): an OAuth 2.1 authorization server that supports the **client credentials grant**, issues **JWT access tokens**, and includes an Angular administration UI for registering REST clients. It also explains how the **WildFly 36 Arquillian integration tests** validate the end-to-end flow.

This setup is intended for **machine-to-machine** authentication. It does **not** implement user-facing OAuth flows such as authorization code, implicit, or device authorization. No browser redirect, login form, or end-user consent step is involved.

---

## 1. Architecture overview

The reference integration test runs **two WildFly 36 instances** on the default HTTP port **8080**, each bound to its own **loopback IP address** within the `127.0.0.0/8` subnet. This matches the SAML and OIDC setup guides: distinct host names without port offsets, and no binding to `0.0.0.0` (which would conflict with any other process already listening on `127.0.0.1:8080`).

| Deployment | WildFly instance | Bind address | Context path | Role |
|------------|------------------|--------------|--------------|------|
| **auth.war** | `wildfly-auth` | `127.0.0.110` | `/auth` | OAuth token endpoint, client registration API, Angular admin UI |
| **api.war** | `wildfly-api` | `127.0.0.111` | `/api` | Sample REST API protected by JWT bearer authentication |

Management interfaces use the same bind address as HTTP on port **9990** for each instance.

```
┌──────────────────────────────┐     ┌──────────────────────────────┐
│ WildFly auth-server          │     │ WildFly api-server           │
│ 127.0.0.110:8080             │     │ 127.0.0.111:8080             │
│                              │     │                              │
│  /auth                       │     │  /api                        │
│  ┌────────────────────────┐  │     │  ┌────────────────────────┐  │
│  │ Angular auth UI        │  │     │  │ BearerJwtAuthFilter    │  │
│  │ POST /api/auth/clients │  │     │  │ GET /version, /user    │  │
│  │ POST /oauth/token      │  │     │  └────────────────────────┘  │
│  └────────────────────────┘  │     └──────────────────────────────┘
└──────────────────────────────┘
         ▲                                    ▲
         │ client_credentials JWT               │ Authorization: Bearer
         └──────────── service account ─────────┘
```

**Client credentials flow (summary):**

1. An operator or automated process registers a confidential OAuth client (via the Angular UI or the registration REST API).
2. The service presents `client_id` and `client_secret` to `POST /auth/oauth/token` with `grant_type=client_credentials`.
3. The authorization server returns a signed **JWT** access token.
4. The service calls protected resources on the API deployment with `Authorization: Bearer <jwt>`.
5. Requests without a valid token receive **401 Unauthorized**.

There is no refresh token in this grant type; when the JWT expires, the client obtains a new access token using the same client credentials request.

---

## 2. Module layout

| Path | Artifact | Purpose |
|------|----------|---------|
| `picketlink/modules/auth/` | `picketlink-auth` | OAuth server, JWT support, sample API resources, servlet bootstrap |
| `picketlink/modules/auth/angular-auth-ui/` | (frontend) | Angular 22 client registration UI |
| `picketlink/modules/auth/angular-auth-ui/angular-auth-ui-it/` | `angular-auth-ui-it` | WildFly 36 + Arquillian Failsafe integration tests |

The Angular UI is built during the `picketlink-auth` Maven lifecycle and packaged at:

`META-INF/resources/auth-ui/`

It is served at runtime by `VirtualResourcesServlet` under the configured URL base (default `/auth-ui`).

---

## 3. Prerequisites

| Requirement | Notes |
|-------------|--------|
| **JDK 17+** | Matches PicketLink 2.5.x / WildFly 36 expectations |
| **Maven 3.8+** | Build and run tests |
| **Node.js 22+** | Required to build the Angular UI (pinned via `.nvmrc` and the frontend Maven plugin) |
| **WildFly 36** | Downloaded automatically by the IT module on first run |
| **Loopback IPs** | `127.0.0.110` and `127.0.0.111` on the `lo` interface (see below) |

For local Angular development only, run `modules/auth/scripts/volta-init.sh` if you use Volta to align Node and npm versions with the project.

### Configure loopback IP addresses (Linux)

Integration tests address the auth server and API on separate loopback IPs in the `127.0.0.0/8` subnet while sharing port **8080**. Assign each address to the loopback interface once per machine (or before each test run if they do not persist):

```bash
sudo ip addr add 127.0.0.110/8 dev lo
sudo ip addr add 127.0.0.111/8 dev lo
```

Verify:

```bash
ip addr show lo | grep -E '127\.0\.0\.(110|111)'
```

The IT build attempts to assign these addresses automatically in the `pre-integration-test` phase. That step requires permission to run `ip addr add`; if it fails, run the commands above manually.

These loopback IPs persist until reboot unless you add them to your network configuration.

---

## 4. Endpoints

Integration test base URLs:

| Role | Base URL |
|------|----------|
| Authorization server | `http://127.0.0.110:8080/auth` |
| Protected API | `http://127.0.0.111:8080/api` |

### Authorization server (`127.0.0.110:8080/auth`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/auth-ui/` | Angular client registration UI |
| `GET` | `/auth/api/auth/clients` | List registered clients |
| `POST` | `/auth/api/auth/clients` | Register a new client (JSON body) |
| `DELETE` | `/auth/api/auth/clients/{clientId}` | Remove a client |
| `POST` | `/auth/oauth/token` | Token endpoint (`grant_type=client_credentials`) |

### Protected API (`127.0.0.111:8080/api`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/version` | Bearer JWT | Returns API version JSON |
| `GET` | `/api/user` | Bearer JWT | Returns `clientId` (and scope) from JWT claims |

Unauthenticated requests to `/api/*` return **401**.

---

## 5. Register a client

### Via the Angular UI

The admin UI is **disabled by default**. `VirtualResourcesServlet` returns **403 Permission denied** until you set servlet init-param `adminUiEnabled` to `true` in `web.xml`. On startup, the server logs a **WARN** message with the exact parameter name if the UI is disabled.

Example `web.xml` fragment:

```xml
<servlet>
  <servlet-name>authUi</servlet-name>
  <servlet-class>org.picketlink.auth.oauth.servlet.VirtualResourcesServlet</servlet-class>
  <init-param>
    <param-name>urlBase</param-name>
    <param-value>/auth-ui</param-value>
  </init-param>
  <init-param>
    <param-name>adminUiEnabled</param-name>
    <param-value>true</param-value>
  </init-param>
</servlet>
```

Open the auth UI (IT example, with `adminUiEnabled=true` in the IT `web.xml`):

`http://127.0.0.110:8080/auth/auth-ui/`

Submit the registration form. The UI calls `POST /auth/api/auth/clients` with the same JSON contract as the REST API.

### Via REST

```bash
curl -s -X POST "http://127.0.0.110:8080/auth/api/auth/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "my-service",
    "clientSecret": "change-me-in-production",
    "tokenEndpointAuthMethod": "client_secret_post",
    "scopes": ["api.read"]
  }'
```

Successful registration returns **201 Created** with the client metadata (including the assigned secret).

Registered clients are persisted through `ClientRegistrationStore`. In the IT deployment, records are written to a JSON file under the WildFly server temp directory.

---

## 6. Obtain a JWT (client credentials)

```bash
curl -s -X POST "http://127.0.0.110:8080/auth/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=my-service" \
  -d "client_secret=change-me-in-production" \
  -d "scope=api.read"
```

Example response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api.read"
}
```

The `access_token` value is a three-part JWT (header.payload.signature), signed with HS256. Claims include `iss`, `sub`, `client_id`, `scope`, `iat`, and `exp`.

Alternative authentication: `client_secret_basic` (HTTP Basic with client id and secret) is supported when configured on the registered client.

---

## 7. Call protected resources

```bash
TOKEN="<access_token from previous step>"

curl -s "http://127.0.0.111:8080/api/version" \
  -H "Authorization: Bearer ${TOKEN}"

curl -s "http://127.0.0.111:8080/api/user" \
  -H "Authorization: Bearer ${TOKEN}"
```

Without a token:

```bash
curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.111:8080/api/version"
# 401
```

---

## 8. JWT configuration

JWT settings are resolved from JVM system properties (or servlet context attributes in a custom deployment). Defaults are suitable for local integration testing only.

| Property | Default (IT) | Description |
|----------|--------------|-------------|
| `picketlink.auth.jwt.secret` | `picketlink-auth-it-secret` | HMAC signing secret (**must be changed in production**) |
| `picketlink.auth.jwt.issuer` | `http://127.0.0.110:8080/auth` | JWT `iss` claim and validation issuer |
| `picketlink.auth.base.url` | `http://127.0.0.110:8080/auth` | Authorization server base URL |
| `test.auth.host` | `127.0.0.110` | Host name used for auth server requests in IT |
| `test.api.host` | `127.0.0.111` | Host name used for API requests in IT |
| `test.http.port` | `8080` | Shared HTTP port for IT |
| `picketlink.auth.jwt.lifetime.seconds` | `3600` | Access token lifetime |

OAuth client registrations are persisted to JSON by default at:

```text
$JBOSS_HOME/standalone/configuration/security/picketlink-auth-clients.json
```

(resolved via `${jboss.server.config.dir}/security/picketlink-auth-clients.json` at runtime). Override with servlet init parameter or system property `picketlink.auth.clients.file`, or set shared directory `picketlink.config.security.dir`.

The auth server issues tokens via `JwtClientCredentialsTokenService`. The API deployment validates them with `BearerJwtAuthenticationFilter` using the same issuer and secret.

---

## 9. Integration tests

The `angular-auth-ui-it` module runs **Failsafe** (not Surefire) with Arquillian controlling **two managed WildFly 36 instances**:

| Arquillian container | `jbossHome` | Bind address | Deployment |
|----------------------|-------------|--------------|------------|
| `auth-server` | `target/wildfly-auth` | `127.0.0.110` | `auth.war` |
| `api-server` | `target/wildfly-api` | `127.0.0.111` | `api.war` |

Each instance is started with `-Djboss.bind.address` and `-Djboss.bind.address.management` set to its loopback IP (not `0.0.0.0`), so the tests do not compete with a default WildFly or other service on `127.0.0.1:8080`.

### Run the tests

From the PicketLink root:

```bash
cd picketlink
mvn -pl modules/auth,modules/auth/angular-auth-ui/angular-auth-ui-it -am verify -Pauth-ui-it
```

The `auth-ui-it` Maven profile adds the IT module to the reactor. It is **not** part of the default `all` profile because it downloads WildFly and adds roughly half a minute to the build.

### What the test verifies

Class: `org.picketlink.auth.it.AuthUiClientCredentialsIT`

1. Angular UI is served at `/auth/auth-ui/index.html`.
2. A client is registered through `POST /auth/api/auth/clients` (same API the UI uses).
3. A JWT is obtained via `grant_type=client_credentials`.
4. `/api/version` and `/api/user` succeed with the bearer token.
5. `/api/version` returns **401** without authentication.

Deployments are built with ShrinkWrap (`AuthUiDeployments`) from `picketlink-auth`, targeted with `@TargetsContainer`, and described in `src/test/resources/deployments/`.

---

## 10. Deploying to your own WildFly

To deploy outside the IT harness:

1. Build `picketlink-auth` (includes the Angular UI in the JAR).
2. Create a WAR that includes:
   - `AuthServerServletContextListener`
   - `VirtualResourcesServlet`, `ClientRegistrationServlet`, `OAuthTokenEndpointServlet`
   - The `picketlink-auth` library (or embedded classes)
   - `adminUiEnabled=true` on `VirtualResourcesServlet` if the Angular admin UI should be served (omit or set to any value other than `true` to keep the UI disabled)
3. Create a separate API WAR (or combine if appropriate) with:
   - `BearerJwtAuthenticationFilter` mapped to `/*`
   - JAX-RS application `SampleRestApplication` (or your own resources)

Ensure both deployments share the same JWT issuer and signing secret. Set the system properties or servlet context attributes before the filter and token service initialize.

The IT module’s `web.xml` and `jboss-web.xml` files under `angular-auth-ui-it/src/test/resources/deployments/` serve as reference descriptors.

---

## 11. Distinction from OpenID Connect authorization flows

PicketLink also provides OpenID Connect support in `picketlink-oidc` (authorization code flow, user login, ID tokens). That path is documented separately in [oidc-setup.md](oidc-setup.md).

| Aspect | Client credentials (this module) | Authorization code (OIDC) |
|--------|----------------------------------|---------------------------|
| **Use case** | Service accounts, backend APIs | Interactive users in a browser |
| **User login** | None | Required |
| **Grant type** | `client_credentials` | `authorization_code` |
| **Typical token** | JWT access token | Access token + ID token |
| **Refresh token** | Not used | Often used |

Choose client credentials when a trusted service authenticates as itself. Choose an authorization flow when a human user must authenticate and delegate access to an application.

---

## 12. Related source locations

| Component | Java package / path |
|-----------|---------------------|
| JWT issue and validation | `org.picketlink.auth.oauth.jwt` |
| Token service | `org.picketlink.auth.oauth.service.JwtClientCredentialsTokenService` |
| Auth WAR bootstrap | `org.picketlink.auth.oauth.servlet.AuthServerServletContextListener` |
| JWT servlet filter | `org.picketlink.auth.oauth.servlet.BearerJwtAuthenticationFilter` |
| Sample REST resources | `org.picketlink.auth.api` |
| Angular UI | `modules/auth/angular-auth-ui/` |
| IT deployments and test | `modules/auth/angular-auth-ui/angular-auth-ui-it/` |
