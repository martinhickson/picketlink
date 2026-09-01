# Tickets — known gaps

| # | Ticket | Status |
|---|---|---|
| PL-101 | Oracle dialect verification deferred — add gated Oracle contract test mirroring the PostgreSQL one so verification runs automatically once `PICKETLINK_TEST_ORACLE_*` env vars exist | Fixed (test gated on env) |
| PL-102 | Admin UI element verified only manually + ad-hoc jsdom smoke — wire the smoke test into the Maven build so CI enforces host-router isolation | Fixed |
| PL-103 | OIDC RP-initiated logout not implemented | Fixed |
| PL-104 | OIDC `request`/`request_uri` authorization parameters silently ignored — must be rejected explicitly per spec (`request_not_supported`) | Fixed |
| PL-105 | Refresh token store is in-memory per server instance — revocation/rotation state lost on restart; add JDBC-backed store (dialect-aware, hashed values) | Fixed |
| PL-106 | Real-browser (GUI) automation of the admin element | Fixed — `npm run test:browser` drives system Chromium headless against the local demo stack (`npm run demo`, fixture API, no external network): 17 checks covering all four screens rendering live data, secret masking, active-key marking, hashed-token display and host-router isolation; screenshots to `/tmp`. jsdom suite (14 checks) remains the Maven-build gate. Also surfaced and fixed two real element bugs: `$localize` crash (i18n attributes without `@angular/localize`) and missing `AdminApiService` provider |
| PL-107 | OIDC provider servlets had no servlet-context bootstrap — deployment required manual assembly | Fixed (`OidcProviderServletContextListener` + `modules/oidc/PROVIDER.md`) |
| PL-108 | OIDC provider login not wired to PicketLink IDM (the project's own identity store) | Fixed — `IdmSubjectAuthenticator` verifies passwords through IDM's credential pipeline and derives standard OIDC profile claims (`email`, `name`, `given_name`, `family_name`, `preferred_username`) from the IDM user via the new `ClaimSource` SPI; ID tokens and UserInfo carry them |
