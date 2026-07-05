# PicketLink IDM Admin

The IDM administration module packages an Angular 22 assistant UI and a WildFly `standalone.xml` configuration service.

## Module layout

| Path | Purpose |
|------|---------|
| `picketlink/modules/idm/admin/idm-admin-ui/` | Angular 22 SPA |
| `picketlink/modules/idm/admin/src/main/java/.../standalone/` | Woodstox StAX `standalone.xml` editor |
| `picketlink/modules/idm/admin/src/main/java/.../servlet/` | JSON API servlets |
| `META-INF/resources/idm-admin-ui/` | Built static assets inside `picketlink-idm-admin` JAR |

## XML editing approach

`standalone.xml` is edited with **Woodstox** (`com.fasterxml.woodstox:woodstox-core`, Apache 2.0): a StAX event pipeline copies the document verbatim and inserts Elytron/Undertow fragments only at explicit closing tags (`</security-domains>`, etc.). Unchanged regions keep their original whitespace so diffs stay readable.

Profiles follow the XML fragments documented in:

- `picketlink/docs/saml-setup.md` section 6.4 (SAML)
- `picketlink/docs/oidc-setup.md` section 6.4 (OIDC Authorization Server)

OIDC Relying Party hosts do not require Elytron `standalone.xml` changes; the assistant explains that case instead of editing the file.

## Safety

1. **Timestamped backup** — `standalone.xml.bak-YYYYMMDD-HHmmss` beside the original file before any mutation.
2. **Idempotent inserts** — existing PicketLink elements (matched by element name + `name` attribute) are not duplicated.
3. **Restart guidance** — the UI lists restart and `org.picketlink` module requirements after apply.
4. **Deployer handoff** — a note reminds operators to provide the updated `standalone.xml` (and backup path) to the deployer team for installation runbook updates.

## Deploy the UI

Serve static assets with `VirtualResourcesServlet` from `picketlink-auth`:

```xml
<servlet>
  <servlet-class>org.picketlink.auth.oauth.servlet.VirtualResourcesServlet</servlet-class>
  <init-param><param-name>urlBase</param-name><param-value>/idm-admin</param-value></init-param>
  <init-param><param-name>resourceBase</param-name><param-value>META-INF/resources/idm-admin-ui</param-value></init-param>
  <init-param><param-name>adminUiEnabled</param-name><param-value>true</param-value></init-param>
</servlet>
<servlet-mapping>
  <servlet-name>idmAdminUi</servlet-name>
  <url-pattern>/idm-admin/*</url-pattern>
</servlet-mapping>
```

Register API servlets:

- `GET /api/idm/standalone/profiles` — `StandaloneConfigServlet`
- `POST /api/idm/standalone/apply?profile=&jbossHome=&removeHttpsListener=` — applies selected profile

## Build

```bash
cd picketlink
mvn -pl modules/idm/admin -am package
```

Skip the Angular build with `-Pskip-ui` on the admin module.

## Pluggable IDM realm document store

Realm users for the OIDC Authorization Server Elytron realm are persisted in a pluggable JSON document (default: file store).

| System property | Default | Description |
|-----------------|---------|-------------|
| `picketlink.idm.document.store` | `file` | `file` or `jdbc` |
| `picketlink.idm.document.file.dir` | `${jboss.server.config.dir}/security` | Security config directory (legacy alias for `picketlink.config.security.dir`) |
| `picketlink.idm.document.file` | `.../security/picketlink-db.json` | Full path to realm JSON file |

When `store=jdbc`, the CLOB table `picketlink_idm.picketlink_idm_clob` is used with optimistic locking on `version`.

### JSON file defaults (zero configuration)

When `store=file` (default), the realm document is stored at:

```text
${jboss.server.config.dir}/security/picketlink-db.json
```

On a typical WildFly layout that resolves to:

```text
$JBOSS_HOME/standalone/configuration/security/picketlink-db.json
```

Override the directory or file:

| Property | Default |
|----------|---------|
| `picketlink.config.security.dir` | `${jboss.server.config.dir}/security` |
| `picketlink.idm.document.file` | `${security.dir}/picketlink-db.json` |
| `picketlink.idm.document.file.dir` | Legacy alias for `picketlink.config.security.dir` |

The JSON envelope still uses document id `picketlink-idm-realm`; only the on-disk filename is `picketlink-db.json`.

### JDBC connection modes

| `picketlink.idm.document.jdbc.connection` | Description |
|-------------------------------------------|-------------|
| `jca` (**default**) | Option 2 — look up a container-managed `javax.sql.DataSource` via JNDI (WildFly / IronJacamar style). |
| `url` | Option 1 — classic `DriverManager` JDBC URL (dev, tests, or non-managed datasources). |

**Option 1 — classic JDBC URL:**

```bash
-Dpicketlink.idm.document.store=jdbc
-Dpicketlink.idm.document.jdbc.connection=url
-Dpicketlink.idm.document.jdbc.url=jdbc:postgresql://db.example.com:5432/idm
-Dpicketlink.idm.document.jdbc.user=idm
-Dpicketlink.idm.document.jdbc.password=secret
-Dpicketlink.idm.document.jdbc.driver=org.postgresql.Driver
```

If `jdbc.url` is set without `jdbc.connection`, classic URL mode is selected automatically for backward compatibility.

**Option 2 — JCA/JNDI (default, enterprise):**

```bash
-Dpicketlink.idm.document.store=jdbc
-Dpicketlink.idm.document.jdbc.jndi=java:jboss/datasources/ExampleDS
```

Or infer the JNDI name from `persistence.xml`:

```bash
-Dpicketlink.idm.document.store=jdbc
-Dpicketlink.idm.document.jdbc.persistence=/META-INF/persistence.xml
```

The store reads `<jta-data-source>` (then `<non-jta-data-source>`) from the persistence unit.

### Pluggable realm provider (document vs SCIM)

The IDM admin UI and `/api/idm/realm/users` use a pluggable realm backend:

| `picketlink.idm.realm.provider` | Description |
|---------------------------------|-------------|
| `document` (**default**) | Local JSON file or JDBC document envelope (`picketlink-db.json` / CLOB). |
| `scim` | Remote SCIM REST server for users, groups, and the PicketLink `/Roles` extension. |

**SCIM endpoints used:**

| Path | Purpose |
|------|---------|
| `/Users` | Standard SCIM users |
| `/Groups` | Standard SCIM groups |
| `/Roles` | PicketLink SCIM extension for role definitions |

**SCIM configuration:**

| Property | Default | Description |
|----------|---------|-------------|
| `picketlink.idm.realm.scim.baseUrl` | *(see below)* | Explicit SCIM base URL |
| `picketlink.idm.realm.scim.useDefaultBaseUrl` | `true` | Infer default base URL when `scim.baseUrl` is unset |
| `picketlink.idm.realm.scim.contextPath` | `/scim` | Context path appended to inferred host/port |
| `picketlink.idm.realm.scim.bearerToken` | *(empty)* | Optional bearer token for SCIM requests |
| `picketlink.idm.realm.scim.syncToDocument` | `true` | Mirror SCIM users into local document store for Elytron FORM login |
| `picketlink.idm.realm.scim.usersPath` | `/Users` | Users collection path |
| `picketlink.idm.realm.scim.groupsPath` | `/Groups` | Groups collection path |
| `picketlink.idm.realm.scim.rolesPath` | `/Roles` | Roles extension path |

**Default SCIM base URL (when enabled):**

```text
http://${jboss.bind.address}:${jboss.http.port}/scim
```

Example explicit configuration:

```bash
-Dpicketlink.idm.realm.provider=scim
-Dpicketlink.idm.realm.scim.baseUrl=https://idp.example.com/scim
-Dpicketlink.idm.realm.scim.bearerToken=secret-token
```

Or use the inferred WildFly default:

```bash
-Dpicketlink.idm.realm.provider=scim
-Dpicketlink.idm.realm.scim.useDefaultBaseUrl=true
```

### Realm provider admin UI

The **Realm provider** page (`/realm-config`) persists settings to:

```text
${jboss.server.config.dir}/security/picketlink-realm-config.json
```

Use it to switch between `document` and `scim` without editing system properties. JVM `-Dpicketlink.idm.realm.*` values still override the file when set (useful for CI and emergency ops).

Fields exposed in the UI:

| Field | Description |
|-------|-------------|
| Provider | `document` or `scim` |
| Use default WildFly SCIM base URL | When enabled, uses `http://${jboss.bind.address}:${jboss.http.port}${scimContextPath}` |
| SCIM base URL | Explicit URL when default is disabled |
| Bearer token | Optional `Authorization: Bearer` header for SCIM requests |
| Sync to document | Mirror SCIM users locally for Elytron FORM password checks |
| Users / Groups / Roles paths | Standard `/Users`, `/Groups`, plus PicketLink `/Roles` extension |

REST API: `GET/POST /api/idm/realm/config`

Integration tests: `IdmAdminUiScimIT` (profile `-Pidm-admin-ui-it`) starts an in-process SCIM mock and verifies config + user CRUD through WildFly.
