# PicketLink Security Design — JWT Issuance, OIDC Provider, SAML

Status: living document · Scope: the modernization program (Phases 1–4)

## 1. What this covers

| Layer | Module | What it does |
|---|---|---|
| JWT issuance management | `picketlink-auth` | Policy-checked, audited, revocable JWT issuance for REST clients and services |
| Persistence + admin | `picketlink-auth` | JSON-in-CLOB stores (SQLite/PostgreSQL/Oracle dialects), admin REST API, embeddable Angular web component |
| OIDC provider | `picketlink-oidc` (`org.picketlink.oidc.provider`) | Authorization code + PKCE, refresh rotation, discovery, UserInfo |
| Spring adapter | `picketlink-spring-integration` | Spring Security resource-server validation of PicketLink JWTs via the issuer's JWKS |
| SAML / WS-Trust | `picketlink-federation` | SAML 2.0 signing/validation on JDK XMLDSig, encryption on Santuario xmlsec 3.0.5 |

Positioning: the **lean, embeddable** identity stack — no separate server to run (vs. Keycloak),
full IdP + federation capability (vs. Spring Security's client-side focus).

## 2. JWT issuance layer — controls and threats

Every token is minted through one chokepoint (`JwtIssuanceManager`):
policy check → claim assembly → sign → register → audit.

| Threat | Control |
|---|---|
| Algorithm confusion / downgrade (`none`, HS-vs-RS) | `SecureSigningAlgorithmRule` allow-list; validators reject `none` and off-list algorithms |
| Long-lived stolen tokens | `MaxTokenLifetimeRule` (server cap + stricter per-client cap), short default lifetimes, revocation registry |
| Token aimed at other resource servers | `AudiencePinningRule` — per-client audience allow-list |
| Static client secrets stolen | RFC 7523 `private_key_jwt` client auth (asymmetric only, HMAC assertions rejected), replay-protected by `jti` cache, 5-minute assertion lifetime window |
| Issuer/key compromise | Keystore-backed signing keys, rotation with overlap window (old keys keep validating; JWKS publishes both), admin-triggered rotation + rollback (`activate`) |
| Silent issuance (no forensics) | `IssuanceAuditListener` — every issue/reject logged with client, scopes, lifetime, algorithm, decision |
| Revocation ignored | With a registry configured, validation requires the token to be present and unexpired (JDBC registry survives restarts; raw JWTs never persisted, only SHA-256 hashes) |
| Cross-tenant claim leakage | Claims assembled centrally; `sub`/`azp`/`client_id`/`scope`/`aud` set by the manager only |

## 3. Admin surface — controls and threats

| Threat | Control |
|---|---|
| Unauthorized admin access | Every admin endpoint requires a bearer JWT with `auth-admin` scope, validated through the same chokepoint (signature/expiry/revocation) — servlet and JAX-RS paths |
| Bootstrap deadlock | `auth-admin` client seeded on first start (secret from `PICKETLINK_ADMIN_CLIENT_SECRET`, generated + logged once if unset) |
| Secret leakage through admin API | Secrets masked (`********`) in listings; returned exactly once on create/rotate |
| UI attacks on host sites | The admin UI is an Angular Elements web component with HashLocationStrategy — it cannot manipulate the host page's routes; API base + token injected by the host |
| Token exposure in browser | Token handled in-memory by the element; the token browser shows hashes only, never raw JWTs |

## 4. OIDC provider — controls and threats

| Threat | Control |
|---|---|
| Authorization code interception | PKCE mandatory (S256 only, `plain` rejected), codes single-use, 60s lifetime, bound to client + redirect URI |
| Redirect URI manipulation | Strict allow-list from client registration; never redirect to an unvalidated URI |
| Refresh token theft | Rotation on use; replaying a rotated token revokes the whole token family |
| Cross-client code/token use | Code client binding + redirect binding re-verified at exchange; refresh client binding checked |
| Forged ID tokens | ID tokens signed by the same issuance chokepoint (policy engine applies), `nonce` echoed |
| Open redirector abuse | Only registered `redirect_uri` values accepted, exact match |

## 5. SAML — controls and threats

| Threat | Control |
|---|---|
| XML signature wrapping (XSW) | Reference-based validation: every Assertion must be covered by a validated reference; Signature elements that fail to unmarshal are rejected (fail closed); regression tests `SAMLAssertionWrappingAttackTestCase` |
| XXE / entity expansion | `DocumentUtil` hardens every parser: DOCTYPE disallowed, external general/parameter entities off; regression tests `ParserHardeningUnitTestCase` |
| Weak crypto | `SamlCryptoSecurityUtil.configureSecureValidation` + disallowed-algorithm screening; xmlsec 3.0.5 (CVE-current), signatures on JDK XMLDSig with secure validation |
| Tampered assertions | Reference digest validation (existing round-trip + tamper tests) |

## 6. Storage

- Clients/policies/keys: JSON documents in one CLOB table (`picketlink_auth`), optimistic locking (`version` column), whole-document atomic rewrites.
- Token records: `picketlink_auth_tokens` keyed by Base64url SHA-256 hash — raw JWTs never persisted.
- Dialect matrix: SQLite + PostgreSQL first-class (tested); Oracle supported at dialect level, verification deferred. **H2 is banned** (see `picketlink/CLAUDE.md`).
- Private signing keys never leave the Java keystore; only kid/algorithm/alias metadata is stored.

## 7. Verification posture

- `picketlink-auth`: 87 tests (issuance policy matrix, client-assertion attack paths, admin
  auth matrix, store round-trips on SQLite, rotation overlap, revoke→introspect flows).
- `picketlink-oidc`: 7 provider flow tests (code+PKCE happy path, replay/rotation, negatives).
- `picketlink-spring-integration`: 7 cross-stack tests — real PicketLink-issued JWTs decoded
  by Spring Security through the published JWKS (happy path, foreign issuer, tampered
  payload, expiry, scope→authority mapping).
- `picketlink-federation`: 259 tests on xmlsec 3.0.5 (XSW, encryption, parser hardening).
- PostgreSQL store contract gated on `PICKETLINK_TEST_POSTGRES_URL`.
- Web component embedding verified headlessly (`element-smoke.mjs`): host router isolation.
- Checkstyle (plugin 3.6.0) clean across all modules.

## 8. Known gaps / next

Previously open gaps are tracked and fixed in `docs/tickets.md` (PL-101..PL-105): Oracle
contract test gated on `PICKETLINK_TEST_ORACLE_*` env (runs automatically once an environment
exists — the dialect SQL is otherwise regression-tested); the admin-element smoke test runs in
the Maven build; RP-initiated logout implemented (`/logout`, registered post-logout URIs
only); `request`/`request_uri` rejected explicitly (`request_not_supported`); refresh tokens
JDBC-backed (`picketlink_oidc_refresh`, hashed values) with rotation and replay detection
surviving restarts.

Remaining (accepted):
- Oracle dialect verification still requires a non-OSS environment to actually execute.

Resolved: real-browser automation of the admin element now runs headless against the local
demo stack (`npm run test:browser`, 17 checks — all screens render live fixture data, secrets
never displayed, active key marked, tokens shown as hashes only, host-router isolation; see
PL-106). The jsdom smoke suite (14 checks, wired into the Maven build) is the always-on gate.
