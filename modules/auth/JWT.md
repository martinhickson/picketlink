# PicketLink JWT — the five-minute path

JWT costs everyone time. This is the shortest path to production-grade tokens — policy,
audit, rotation and revocation included — plus the client side nobody else ships.

## Issuer: five lines

```java
PicketLinkJwt jwt = PicketLinkJwt.issuer("https://auth.example")
        .ed25519()                        // or .rs256() / .es256() / .keyPair(pair, RS256)
        .audience("https://api.example")  // audience pinning for all issued tokens
        .build();

String token  = jwt.issue("user-42", Set.of("read", "write"));
JwtClaims who = jwt.validate(token);      // signature + issuer + time + revocation
jwt.revoke(token);                        // that token is dead everywhere
```

What those five lines get you:

| Capability | Details |
|---|---|
| Algorithms | RS256, ES256 (proper ECDSA/JOSE signature conversion), **Ed25519/EdDSA** (JCA-native, published as OKP JWK per RFC 8037) |
| Policy engine | lifetime caps (15 min default / 1 h max), audience pinning, algorithm allow-list |
| Key rotation | `jwt.rotate()` — new key active, old key stays verifiable (overlap window), both in `jwt.jwks()` |
| Revocation | issued tokens registered; `revoke()` kills them through the same validation path |
| Clock skew | 30 s leeway on expiry/not-before (configurable) — no more 1-second-flake failures |
| Audit | `.audit(listener)` receives every issue/reject decision |

Custom policy rules, JDBC revocation registries and keystore-backed keys are available via
the full `JwtIssuanceManager` API this facade wraps.

## Resource server: requirement checks

```java
JwtClaims claims = jwt.validate(token,
        JwtRequirements.requireAudience("https://api.example")
                .scope("read")
                .subject("user-42"));
```

Cryptographic validation runs first (signature, issuer, expiry with skew, revocation),
then audience/scope/subject checks — `JwtValidationException` says exactly which failed.

Spring Security resource servers: use `picketlink-spring-integration`
(`PicketLinkJwtDecoders.fromIssuer(...)`); it refreshes keys from `/.well-known/jwks.json`
automatically across rotations.

## Client side: the TokenClient

The part that eats afternoons — fetching, caching, refreshing tokens for service-to-service
calls — is one object (JDK-only, thread-safe, refreshes ~30 s before expiry):

```java
TokenClient client = TokenClient.forClientCredentials(
        "https://auth.example/oauth/token", "my-client", "my-secret");

serviceCall(client.token());   // cached; auto-refreshed as expiry approaches
client.invalidate();           // after a 401 — next token() fetches fresh
```

## Full stack

The facade is the on-ramp: the same issuance chokepoint backs OAuth2 client-credentials
(RFC 7523 `private_key_jwt` for secret-free machine clients), the OIDC provider, SCIM
provisioning, the admin web console and the Spring adapter. See
`docs/security-design.md` for the architecture and threat model.
