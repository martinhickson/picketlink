# PicketLink Spring Integration

Spring Security resource-server support for PicketLink-issued JWTs. Spring applications
validate tokens against the issuer's published JWKS — no PicketLink runtime needed on the
resource-server side.

## Usage

```java
@Bean
JwtDecoder jwtDecoder() {
    // resolves <issuer>/.well-known/jwks.json with automatic key refresh/rotation
    return PicketLinkJwtDecoders.fromIssuer("https://auth.corp.example");
}

@Bean
SecurityFilterChain apiSecurity(HttpSecurity http, JwtDecoder decoder) throws Exception {
    http.authorizeHttpRequests(authz -> authz
            .requestMatchers("/api/**").hasAuthority("SCOPE_read")
            .anyRequest().authenticated())
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt
            .decoder(decoder)
            .jwtAuthenticationConverter(new PicketLinkJwtAuthenticationConverter())));
    return http.build();
}
```

- `PicketLinkJwtDecoders.fromIssuer(issuer)` — JWKS-URI decoder (recommended; keys refresh
  automatically across PicketLink rotations). Accepts RS256/ES256 (the policy-approved
  algorithms), enforces the exact issuer, `exp`/`nbf` with 60s clock skew.
- `PicketLinkJwtDecoders.fromJwksUri(uri, issuer)` — explicit JWKS URI variant.
- `PicketLinkJwtDecoders.fromStaticJwks(json, issuer)` — pinned single-key decoder for tests.
- `PicketLinkJwtAuthenticationConverter` — maps the PicketLink `scope` claim (space-separated
  string) to `SCOPE_*` authorities, principal = token subject.

## Dependencies

Spring Security jars are `provided` — the consuming application supplies its own version
(built and verified against 6.x; needs `spring-security-oauth2-jose` and
`spring-security-oauth2-resource-server`).

## Verification

Tests issue real JWTs through the PicketLink issuance signing service, publish its JWKS over
HTTP, and decode through the Spring stack: happy path, foreign issuer rejection, tampered
payload rejection, expired token rejection, scope→authority mapping.
