# Security review and hardening notes for issue #112

This note captures the focused product-surface security pass completed for issue #112.
It is intentionally about the shipped **admin dashboard + Crypto API product boundary**, not host hardening.

## Review scope

Reviewed surfaces:

- admin dashboard authentication and session handling
- customer-facing Crypto API authentication and alias/policy authorization
- API key handling and public error behavior
- shared SQLite-backed control-plane persistence exposure
- exposed HTTP endpoints and container/operator-facing defaults
- operator-facing docs for the above behavior

## Concrete gaps identified

### 1. Public Crypto API diagnostics leaked more than necessary

The customer-facing host exposed:

- detailed API-key authentication failure reasons (`not found`, `revoked`, `expired`, etc.)
- detailed key-alias authorization failure reasons (`alias not found`, policy mismatch, invalid stored policy document)
- shared-state metadata including SQLite connection target/path and record counts

That was useful for private debugging, but too chatty as a default internet-facing or semi-exposed API surface.
It increased enumeration and deployment-fingerprint leakage without being required for normal clients.

### 2. Admin login/logout endpoints needed explicit request verification

The admin dashboard already rendered antiforgery tokens in forms, but the `/account/login` and `/account/logout` minimal endpoints were manually reading forms and did not explicitly validate the antiforgery token at the endpoint boundary.

### 3. Admin HTTP responses were missing a few low-cost browser hardening defaults

The admin UI did not consistently emit response headers that reduce common browser-side attack surface:

- clickjacking protection
- MIME sniffing suppression
- referrer suppression
- cache suppression on especially sensitive auth/export routes

### 4. Admin auth cookie defaults could be tightened

Cookie auth was functional, but the configuration did not explicitly lock in:

- `HttpOnly`
- `SameSite=Lax`
- request-aware secure cookie policy
- bounded session lifetime

## Fixes applied

### Crypto API

Added `CryptoApiSecurity` configuration with secure-by-default behavior:

```json
"CryptoApiSecurity": {
  "ExposeDetailedErrors": false,
  "ExposeSharedStateDetails": false
}
```

Default behavior now:

- authentication failures return a generic rejection message
- authorization failures return a generic access-denied message
- `/api/v1/shared-state` returns a reduced public document without connection target or record counts

Private/internal operators can still opt back into the previous verbose diagnostics by setting:

- `CryptoApiSecurity__ExposeDetailedErrors=true`
- `CryptoApiSecurity__ExposeSharedStateDetails=true`

### Admin dashboard

Hardened the local-cookie auth surface by:

- explicitly validating antiforgery tokens on login/logout POST endpoints
- returning a clean `400` problem response when the token is missing/invalid
- setting cookie auth defaults to `HttpOnly`, `SameSite=Lax`, and an 8-hour session lifetime
- adding response hardening headers:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `Permissions-Policy: camera=(), geolocation=(), microphone=()`
- disabling caching on login/account/export routes

## Remaining risks and honest boundaries

These are **not** fixed by this issue and should remain explicit in docs/roadmap discussions:

1. **Local admin auth is still local-user/cookie based.**
   There is still no MFA, external IdP, SSO, hardware-backed admin auth, or centralized session revocation.

2. **Login throttling is still in-memory per process.**
   It helps against casual brute force but resets on process restart and is not shared across multiple admin instances.

3. **Crypto API rate limiting is still not built in.**
   Upstream gateways/load balancers should still enforce request-rate, body-size, and abuse controls.

4. **SQLite is still the shared control-plane backend.**
   That remains acceptable only for the documented conservative deployment model with trustworthy file-locking/WAL semantics.

5. **Security headers are intentionally conservative.**
   A strict CSP was not added in this pass because the current interactive admin UI would need CSP-specific tuning/testing rather than a guessy header that could break the product.

6. **No active Swagger/OpenAPI generator was found in the current tree.**
   If a Swagger/OpenAPI surface is added later, it should be treated as another public attack surface and gated appropriately rather than assumed safe by default.

## Validation expectation for this issue

Validation should include at least:

- targeted Crypto API route tests for generic error behavior and sanitized shared-state output
- admin integration tests proving hardening headers are present and tokenless login POSTs fail
- normal repo build/test validation for the touched projects
