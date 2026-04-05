# Crypto API host scaffold + API key lifecycle + first customer-facing operations

`Pkcs11Wrapper.CryptoApi` is the first machine-facing service host for the repository.

It is intentionally **thin** and intentionally **separate** from the admin dashboard stack.

For the operator-facing deployment model covering **one admin dashboard + many stateless Crypto API instances**, shared-state boundaries, and container guidance, see [docs/crypto-api-deployment.md](docs/crypto-api-deployment.md). For the repo-owned YARP ingress layer that can front those instances, see [docs/crypto-api-gateway.md](docs/crypto-api-gateway.md). This page stays focused on the host surface itself.

## Why this host exists

The repo now has two different application boundaries:

- **`Pkcs11Wrapper.Admin.Web`**
  - operator-facing Blazor Server dashboard
  - local auth, local storage, audit chain, protected PIN cache, configuration transfer
  - optimized for trusted human operators on a bounded host
- **`Pkcs11Wrapper.CryptoApi`**
  - machine-facing ASP.NET Core API host
  - no local operator UI
  - no per-node auth/policy files
  - intended to scale out as **many stateless instances** behind a load balancer or gateway

That separation keeps the product model simple for now:

> one admin dashboard + many stateless crypto API instances

The admin app remains the place for operations and governance. The crypto API host is now the place for the first customer-facing sign / verify / random workflows, with future room for broader crypto contracts.

## Current scaffold contents

The current slice is still deliberately small, but now includes the first practical API client / API key lifecycle foundation plus the first useful customer-facing crypto endpoints:

- dedicated `src/Pkcs11Wrapper.CryptoApi` project in the solution
- ASP.NET Core host with DI + configuration binding
- service document at `/`
- versioned route group rooted at `/api/v1`
- runtime descriptor endpoint at `/api/v1/runtime`
- explicit operation namespace at `/api/v1/operations`
- alias-routing + policy-check endpoint at `/api/v1/operations/authorize`
- customer-facing sign endpoint at `/api/v1/operations/sign`
- customer-facing verify endpoint at `/api/v1/operations/verify`
- customer-facing random endpoint at `/api/v1/operations/random`
- shared-state descriptor endpoint at `/api/v1/shared-state`
- authenticated self-introspection endpoint at `/api/v1/auth/self`
- built-in customer-endpoint rate limiting with predictable `429 Too Many Requests` + `Retry-After` responses
- liveness endpoint at `/health/live`
- readiness endpoint at `/health/ready`
- readiness check that attempts to load the configured PKCS#11 module via `Pkcs11Module.Load(...)`
- shared persistence for:
  - API clients / applications
  - API client keys / key identifiers
  - key aliases
  - policy documents
  - client-to-policy and alias-to-policy bindings
- generated API key secrets that are revealed once, hashed before persistence, and tracked with disable / revoke / expiry / last-used metadata
- admin control-plane workflow in `Pkcs11Wrapper.Admin.Web` via the **Crypto API Access** page when it is configured against the same shared store, including client/key lifecycle plus alias/policy/binding management
- dedicated test project covering base-path normalization, runtime descriptor metadata, readiness health behavior, shared-state round-tripping, lifecycle management, schema migration behavior, and customer-facing route/integration coverage

## Runtime model

The host is still designed around a **stateless request pipeline**:

- no host-local portal/session state
- no per-node JSON database or app data root for API auth/policy data
- no operator identity system inside the API host in this slice
- each API instance should remain replaceable without local state migration
- environment/config drives module selection and network exposure
- durable API auth/policy state is allowed only when it lives in a **shared persistence backend**

That means the API host stays stateless from the instance point of view even though shared durable data now exists for the state that would otherwise break under scale-out.

Steady-state request execution is now intentionally **two-tiered**:

- the source of truth for auth, alias, and policy state remains the shared persistence store
- each API node keeps a small bounded in-memory cache for successful auth and authorization decisions
- in Postgres-only deployments, each node also keeps a Postgres-backed auth-state revision hint current via `LISTEN` / `NOTIFY`, so warm request paths do not have to re-read the revision row on every call
- operators can optionally add Redis as a **shared hot-path accelerator** for auth revision lookups, successful auth/authz cache reuse across nodes, and fleet-wide `last_used_at_utc` write throttling
- cache entries are keyed by a lightweight shared-state auth revision so admin changes still invalidate warm entries across nodes without forcing full snapshot reloads on every request
- `last_used_at_utc` updates are throttled to a short interval per key instead of writing synchronously on every successful request

This keeps the instance stateless in the deployment sense while removing avoidable per-request PBKDF2, full-snapshot, and shared-store write overhead from the hot path.
Redis does **not** become a second control plane; if Redis is unavailable or cold, the host falls back to the relational/shared store path.

## Shared persistence approach

The host now standardizes on **PostgreSQL** for shared persistence across local/dev/lab and production-oriented deployments.

That keeps the control-plane model simple:

- every Crypto API instance and the admin dashboard point at the same PostgreSQL database when they share one control plane
- PostgreSQL remains the authoritative source of truth for clients, keys, aliases, policies, bindings, last-used metadata, and auth-state revision
- Redis can still be layered on as optional hot-path acceleration, but it does not become a second control plane
- higher layers keep the same `ICryptoApiSharedStateStore` contract, just without a SQLite branch to document, validate, and support

### Shared-ready state

The store prepares the state that cannot safely stay per-node local once API instances scale out:

- **API clients / applications**
  - stable client identity
  - human display metadata
  - application type metadata (`gateway`, `worker`, etc.)
  - auth mode metadata
  - enable/disable state
- **API client keys**
  - stable public key identifier (`kid`-style metadata)
  - generated secret shown only at creation time
  - salted PBKDF2 hash persisted instead of plaintext
  - secret hint for operator troubleshooting without recoverability
  - disable, revoke, expiry, and last-used metadata for lifecycle readiness
- **Key aliases**
  - stable alias name used by customer-facing API requests
  - internal routing metadata (`route_group_name` for pooled routing, or legacy `device_route`/`slot_id`, plus object label / object-id hex)
  - raw PKCS#11 locator details stay in shared state and internal services, not in the customer-facing response surface
- **Policies**
  - versioned JSON policy document payload
  - pragmatic v1 model: allowed operation list (for example `sign`, `verify`, `random`)
  - enable/disable state
- **Bindings**
  - client → policy
  - alias → policy
  - authorization succeeds only when an enabled client and enabled alias share at least one enabled policy whose document allows the requested operation

That gives the repo a concrete place to keep request authentication, alias resolution, and policy enforcement inputs outside any single node.

## Configuration

Current settings live under three sections:

```json
{
  "CryptoApiHost": {
    "ServiceName": "Pkcs11Wrapper.CryptoApi",
    "ApiBasePath": "/api/v1"
  },
  "CryptoApiRuntime": {
    "DisableHttpsRedirection": false,
    "ModulePath": "/usr/lib/libsofthsm2.so",
    "UserPin": "98765432",
    "Backends": [
      {
        "Name": "hsm-eu-primary",
        "ModulePath": "/usr/lib/libvendorhsm.so",
        "UserPin": "98765432"
      },
      {
        "Name": "hsm-eu-secondary",
        "ModulePath": "/usr/lib/libvendorhsm.so",
        "UserPin": "98765432"
      }
    ],
    "RouteGroups": [
      {
        "Name": "payments-signers",
        "SelectionMode": "priority",
        "Backends": [
          { "BackendName": "hsm-eu-primary", "SlotId": 7, "Priority": 10 },
          { "BackendName": "hsm-eu-secondary", "SlotId": 7, "Priority": 20 }
        ]
      }
    ]
  },
  "CryptoApiSharedPersistence": {
    "Provider": "Postgres",
    "ConnectionString": "Host=db.internal;Port=5432;Database=pkcs11wrapper_cryptoapi;Username=cryptoapi;Password=change-me;SSL Mode=Require",
    "AutoInitialize": true
  },
  "CryptoApiRequestPathCaching": {
    "Redis": {
      "Enabled": true,
      "Configuration": "redis.internal:6379,password=change-me,ssl=false",
      "InstanceName": "pkcs11wrapper:cryptoapi:",
      "ConnectTimeoutMilliseconds": 5000,
      "OperationTimeoutMilliseconds": 1000,
      "ReconnectCooldownSeconds": 5,
      "AuthStateRevisionTtlSeconds": 300,
      "AuthenticationEntryTtlSeconds": 0,
      "AuthorizationEntryTtlSeconds": 0
    }
  }
}
```

Observability settings now live under a fourth section:

```json
"Observability": {
  "EnablePrometheusScrapingEndpoint": true,
  "MetricsPath": "/metrics"
}
```

Notes:

- if `Backends` is omitted, the top-level `ModulePath` / `UserPin` pair is treated as the default backend runtime
- route groups still work in that single-runtime mode; backend names then act as logical route labels while execution reuses the default local module
- new aliases should prefer `route_group_name`; keep direct `device_route` / `slot_id` only for legacy one-route bindings

Notes:

- `CryptoApiHost:ApiBasePath` defines where machine-facing routes live.
- `CryptoApiRuntime:ModulePath` is required for readiness because the host is not actually ready to serve crypto traffic until it can load a PKCS#11 module.
- `CryptoApiRuntime:UserPin` is optional but practically required for many sign / HMAC / private-object flows. Treat it as deployment secret material, not as checked-in config.
- `CryptoApiRuntime:DisableHttpsRedirection=true` is useful for local/container smoke flows behind a trusted reverse proxy or local HTTP test loop.
- `CryptoApiSharedPersistence:Provider` supports `Postgres`.
- `CryptoApiSharedPersistence:ConnectionString` enables the shared state store. If omitted, the host still runs, but `/api/v1/shared-state` reports that shared persistence is not configured.
- `CryptoApiSharedPersistence:AutoInitialize=true` creates the schema on startup/first use.
- With `AutoInitialize=false`, the host stops treating status/read endpoints as implicit schema bootstrap paths; use that mode after first deployment if you want startup/status checks to fail fast instead of issuing DDL.
- With `Provider=Postgres`, use a standard Npgsql/PostgreSQL connection string and prefer a dedicated database/role for the Crypto API control plane.
- If the connection string does not specify `Maximum Pool Size` / `Max Pool Size`, the host applies a conservative default cap of `32` pooled Postgres connections per instance. Set an explicit pool size in the connection string if your deployment needs a different budget.
- Each instance also keeps one dedicated **unpooled** Postgres `LISTEN` connection for auth-state revision invalidation. That listener does **not** consume one of the pooled request connections.
- If the Postgres connection string does not set `Keepalive`, the dedicated listener defaults to a 30-second keepalive so long-lived `LISTEN` sockets survive common idle network appliances more reliably. Set an explicit `Keepalive` value in the connection string if your environment needs a different cadence.
- `CryptoApiRequestPathCaching:Redis:Enabled=true` turns on the optional Redis-backed hot-path accelerator.
- `CryptoApiRequestPathCaching:Redis:Configuration` is a standard StackExchange.Redis configuration string.
- `CryptoApiRequestPathCaching:Redis:InstanceName` prefixes cache/lease keys so multiple environments can share one Redis fleet safely.
- Redis hot-path keys now live under a versioned `hotpath:v2:` namespace beneath `InstanceName`, so cache-key format changes can roll out without pretending old entries are still valid.
- `CryptoApiRequestPathCaching:Redis:ReconnectCooldownSeconds` bounds how quickly an instance retries Redis connection establishment after a failure, which avoids reconnect storms when Redis is unhealthy.
- `CryptoApiRequestPathCaching:Redis:AuthStateRevisionTtlSeconds` bounds how long the shared auth-revision hint lives in Redis before the service refreshes it from the relational source of truth.
- `CryptoApiRequestPathCaching:Redis:AuthenticationEntryTtlSeconds` and `AuthorizationEntryTtlSeconds` optionally override the shared L2 TTL for successful auth/authz entries. Leave them at `0` to follow the local request-path cache TTL, or set them explicitly when you want a different Redis sharing window.
- When Redis acceleration is enabled, warm instances can reuse successful auth/authz decisions across the fleet and coordinate `last_used_at_utc` throttling, but correctness still comes from the shared persistence store plus the auth-state revision.
- Repo-managed client/key/alias/policy/binding writes refresh the shared auth-state revision in Redis immediately after commit, and that revision hint only moves forward. A late/stale writer cannot roll the Redis hint back to an older revision.
- Distributed auth/authz entries stay revision-scoped and still age out naturally; the service does not try to sweep Redis with delete scans on every control-plane write.
- Redis auth/authz TTLs are clamped to the API key expiry when one exists, so an expiring key does not outlive its own credential lifetime in the distributed cache.
- If some external actor changes the database behind the repo's back, Redis still does not become authoritative; the revision hint simply ages out and is re-read from the source of truth on the configured TTL.
- `CryptoApiRateLimiting` adds built-in limits for `/api/v1/auth/self` and the customer-facing `/api/v1/operations/*` POST routes.
- The first slice is intentionally **instance-local**, not shared across the fleet. A caller can consume up to the configured budget on each Crypto API instance behind the load balancer.
- Partitioning is keyed by the presented `X-Api-Key-Id` header when present, with remote-IP fallback when no key id is available.
- Rejections do not queue by default; the host immediately returns `429 Too Many Requests` and includes `Retry-After` plus a problem-details body so machine clients can back off deterministically.
- The admin panel can point at the same `CryptoApiSharedPersistence` section to stay on the same shared control-plane data model used for clients, aliases, policies, and bindings.

For the full operator deployment model, see [docs/crypto-api-deployment.md](docs/crypto-api-deployment.md).
If you are wrapping this host in your own container or supervisor, start from `deploy/container/crypto-api.env.example`.
For the metric catalogue and Grafana starter dashboard, see [docs/runtime-observability.md](docs/runtime-observability.md).

## Local run example

```bash
cd src/Pkcs11Wrapper.CryptoApi
export CryptoApiRuntime__ModulePath=/usr/lib/libsofthsm2.so
export CryptoApiRuntime__UserPin=98765432
export CryptoApiRuntime__DisableHttpsRedirection=true
export CryptoApiSharedPersistence__Provider=Postgres
export CryptoApiSharedPersistence__ConnectionString='Host=127.0.0.1;Port=5432;Database=pkcs11wrapper_cryptoapi;Username=cryptoapi;Password=ChangeMe;SSL Mode=Disable'
dotnet run
```

Useful endpoints:

- `/`
- `/health/live`
- `/health/ready`
- `/api/v1`
- `/api/v1/runtime`
- `/api/v1/operations`
- `/api/v1/shared-state`
- `/api/v1/auth/self` using `X-Api-Key-Id` + `X-Api-Key-Secret`
- `POST /api/v1/operations/authorize` using `X-Api-Key-Id` + `X-Api-Key-Secret` with `{ "keyAlias": "payments-signer", "operation": "sign" }`
- `POST /api/v1/operations/sign` using `X-Api-Key-Id` + `X-Api-Key-Secret` with `{ "keyAlias": "payments-signer", "algorithm": "RS256", "payloadBase64": "aGVsbG8=" }`
- `POST /api/v1/operations/verify` using `X-Api-Key-Id` + `X-Api-Key-Secret` with `{ "keyAlias": "payments-signer", "algorithm": "RS256", "payloadBase64": "aGVsbG8=", "signatureBase64": "..." }`
- `POST /api/v1/operations/random` using `X-Api-Key-Id` + `X-Api-Key-Secret` with `{ "keyAlias": "payments-signer", "length": 32 }`
- `/metrics` when `Observability:EnablePrometheusScrapingEndpoint=true`

`/api/v1/shared-state` returns a reduced public summary by default. Detailed connection-target and count metadata stay hidden unless you explicitly enable `CryptoApiSecurity:ExposeSharedStateDetails`.
`/api/v1/auth/self` validates the hashed shared secret, enforces disabled / revoked / expired state, updates last-used metadata, and returns the authenticated client context that future crypto operations can reuse.
`POST /api/v1/operations/authorize` remains the low-level alias/policy check.
`POST /api/v1/operations/sign`, `verify`, and `random` reuse that same authentication + authorization model and keep the public contract stable and customer-facing: callers provide alias names, high-level algorithms such as `RS256` / `PS256` / `ES256` / `HS256`, and base64 payloads instead of raw PKCS#11 device/slot/handle details.

### Built-in rate limiting behavior

The host now ships a practical first built-in rate-limiting slice for customer-facing routes:

- `/api/v1/auth/self`
  - default budget: **60 requests / minute / presented API key id**
- `/api/v1/operations/authorize`
- `/api/v1/operations/sign`
- `/api/v1/operations/verify`
- `/api/v1/operations/random`
  - default budget: **600 requests / minute / presented API key id / instance**

Why this shape:

- it protects the public Crypto API surface without introducing shared counter writes into the control-plane data store
- it keeps the API instances stateless and horizontally replaceable
- it gives machine callers deterministic backoff behavior instead of silent slowdowns or long server-side queues

Important caveats:

- the limiter is **not cluster-global**; multiple API instances mean multiple per-instance budgets
- the limiter runs before full authentication/authorization, so the presented key id is the practical partition key
- upstream ingress/gateway policy should still enforce fleet-wide quotas, body-size limits, and abuse controls; the repository gateway host in `src/Pkcs11Wrapper.CryptoApi.Gateway` is the current first-class reference ingress for that role

Rejected requests return:

- HTTP `429 Too Many Requests`
- `Retry-After` response header when the limiter can compute it
- an `application/problem+json` body with machine-friendly scope / mode metadata

### Crypto API security defaults

The host now defaults to a safer public diagnostic posture:

```json
"CryptoApiSecurity": {
  "ExposeDetailedErrors": false,
  "ExposeSharedStateDetails": false
}
```

That means:

- auth failures return generic rejection text by default
- alias/policy authorization failures return generic access-denied text by default
- `/api/v1/shared-state` omits the shared-store connection target and record counts by default

For private/internal troubleshooting, operators can opt back into the verbose behavior with:

- `CryptoApiSecurity__ExposeDetailedErrors=true`
- `CryptoApiSecurity__ExposeSharedStateDetails=true`

## Intentionally out of scope for this issue

This scaffold still does **not** yet add:

- broader crypto contracts such as encrypt/decrypt/wrap/unwrap or key metadata lookup
- OAuth/OIDC or broader external authn/authz protocol handling beyond the first shared API-key slice
- tenant routing / portal concepts / edge orchestration
- durable job/workflow processing state
- a customer self-service portal or duplicated operator UI inside the API host

Those can land incrementally once the machine-facing contract expands.
