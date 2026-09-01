# PicketLink SCIM 2.0 Identity Service

`org.picketlink.idm.rest.ScimServlet` implements **SCIM 2.0 (RFC 7643/7644)** — the REST
identity API corporate systems already speak — over a configured IDM `PartitionManager`.
Corporate apps provision and manage users/groups against the database they already own
(JSON-in-CLOB via the shared dialect layer, or any IDM store: file, JPA, LDAP), and the
PicketLink OIDC provider (`IdmSubjectAuthenticator`) or SAML logins authenticate those same
identities immediately.

## Endpoints (map the servlet at `/scim/v2/*`)

| Method | Path | Operation |
|---|---|---|
| GET | `/ServiceProviderConfig` | capabilities (filter: yes, patch: no, changePassword: yes) |
| GET/POST | `/Users` | list (optional `filter=userName eq "x"`) / create |
| GET/PUT/DELETE | `/Users/{id}` | fetch / replace (profile + password) / deactivate |
| GET/POST | `/Groups` | list (optional `filter=displayName eq "x"`) / create with members |
| GET/PUT/DELETE | `/Groups/{id}` | fetch / **replace** membership / delete |

- Media type `application/scim+json`; RFC list-response envelopes and error responses
- Passwords: SCIM `passwords` attribute (`[{"value":"...","primary":true}]`), stored through
  IDM's credential pipeline (hashing/encoding as configured) — never returned
- PUT on a group replaces the membership array (spec semantics)
- PATCH is advertised as unsupported — use PUT

## Security

Every request must pass `IdentityRestAccess`:
- simplest: servlet init-param `identityRestToken` (static bearer, constant-time compare)
- custom: constructor `new ScimServlet(partitionManager, access)` — e.g. an adapter over the
  auth module's `JwtIssuanceManager` (`scope auth-admin` style tokens)

Default is deny-all. Never expose the service without one of these.

## web.xml sketch

```xml
<servlet>
  <servlet-name>Scim</servlet-name>
  <servlet-class>org.picketlink.idm.rest.ScimServlet</servlet-class>
  <init-param>
    <param-name>identityRestToken</param-name>
    <param-value>${SCIM_SERVICE_TOKEN}</param-value>
  </init-param>
</servlet>
<servlet-mapping>
  <servlet-name>Scim</servlet-name>
  <url-pattern>/scim/v2/*</url-pattern>
</servlet-mapping>
```

The `PartitionManager` is taken from the servlet context attribute
`org.picketlink.idm.PartitionManager` (set it in your listener) or the constructor.

## Version note

`modules/rest` ships SCIM 1.1 endpoints (CDI/JAX-RS based, outside the default reactor) —
kept as reference. `ScimServlet` is the supported SCIM 2.0 path.
