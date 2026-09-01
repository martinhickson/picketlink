# Project Rules

## Database rules (picketlink-auth JDBC store and friends)

- **H2 is BANNED** as a test or runtime database in this repository. Do not add the
  `com.h2database:h2` dependency, do not use `jdbc:h2:` URLs, do not reference H2 in
  code, tests, or documentation. Existing H2 usage must be migrated out on contact.
- The JDBC persistence layer must work across a **dialect matrix**: **SQLite** and
  **PostgreSQL** are first-class and must be covered by tests; **Oracle** is supported at
  the dialect level but its verification is deferred (not OSS) — do not gate the build on it.
- All SQL must flow through `org.picketlink.auth.oauth.store.SqlDialect` implementations
  (`SqlDialects.forUrl(...)` auto-detects). No driver-specific SQL may be inlined in store
  classes (e.g. no `MERGE INTO ... KEY`, no raw `LIMIT` outside the dialect).
- Tests use **SQLite** (`org.xerial:sqlite-jdbc`) as the default embedded database.
  PostgreSQL integration tests are gated on the `PICKETLINK_TEST_POSTGRES_URL` environment
  variable (plus `PICKETLINK_TEST_POSTGRES_USER` / `PICKETLINK_TEST_POSTGRES_PASSWORD`) and
  must self-skip when it is not set.
