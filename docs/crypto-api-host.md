# Crypto API host scaffold + API key lifecycle + first customer-facing operations

`Pkcs11Wrapper.CryptoApi` is the first machine-facing service host for the repository.

It is intentionally **thin** and intentionally **separate** from the admin dashboard stack.

For the operator-facing deployment model covering **one admin dashboard + many stateless Crypto API instances**, shared-state boundaries, and container guidance, see [docs/crypto-api-deployment.md](docs/crypto-api-deployment.md). This page stays focused on the host surface itself.

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
- liveness endpoint at `/health/live`
- readiness endpoint at `/health/ready`
- readiness check that attempts to load the configured PKCS#11 module via `Pkcs11Module.Load(...)`
- shared SQLite-backed persistence for:
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

## Shared persistence approach

The first persistence provider is intentionally pragmatic: **SQLite via a shared database file**.

Why this first:

- it is real and immediately usable
- it keeps the initial auth/policy state model simple
- it avoids inventing a full control-plane or migration system before the public crypto contract exists
- it is enough for small-to-medium deployments where API instances share a mounted volume or otherwise coordinate through the same SQLite file

This is **not** claiming SQLite is the final answer for every distributed deployment.
For larger/server-grade topologies, the stored concepts can move to another relational backend later without changing the basic state model introduced here.

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
  - internal routing metadata (`device_route`, `slot_id`, object label, object-id hex)
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
    "UserPin": "98765432"
  },
  "CryptoApiSharedPersistence": {
    "Provider": "Sqlite",
    "ConnectionString": "Data Source=/srv/pkcs11wrapper-cryptoapi/shared-state.db",
    "AutoInitialize": true
  }
}
```

Notes:

- `CryptoApiHost:ApiBasePath` defines where machine-facing routes live.
- `CryptoApiRuntime:ModulePath` is required for readiness because the host is not actually ready to serve crypto traffic until it can load a PKCS#11 module.
- `CryptoApiRuntime:UserPin` is optional but practically required for many sign / HMAC / private-object flows. Treat it as deployment secret material, not as checked-in config.
- `CryptoApiRuntime:DisableHttpsRedirection=true` is useful for local/container smoke flows behind a trusted reverse proxy or local HTTP test loop.
- `CryptoApiSharedPersistence:Provider` currently supports only `Sqlite`.
- `CryptoApiSharedPersistence:ConnectionString` enables the shared state store. If omitted, the host still runs, but `/api/v1/shared-state` reports that shared persistence is not configured.
- `CryptoApiSharedPersistence:AutoInitialize=true` creates the schema on startup/first use.
- The admin panel can point at the same `CryptoApiSharedPersistence` section to stay on the same shared control-plane data model used for clients, aliases, policies, and bindings.

For the full operator deployment model, see [docs/crypto-api-deployment.md](docs/crypto-api-deployment.md).
If you are wrapping this host in your own container or supervisor, start from `deploy/container/crypto-api.env.example`.

## Local run example

```bash
cd src/Pkcs11Wrapper.CryptoApi
export CryptoApiRuntime__ModulePath=/usr/lib/libsofthsm2.so
export CryptoApiRuntime__UserPin=98765432
export CryptoApiRuntime__DisableHttpsRedirection=true
export CryptoApiSharedPersistence__ConnectionString='Data Source=/tmp/pkcs11wrapper-cryptoapi-shared.db'
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

`/api/v1/shared-state` returns provider/schema/count metadata when the shared store is configured and available.
`/api/v1/auth/self` validates the hashed shared secret, enforces disabled / revoked / expired state, updates last-used metadata, and returns the authenticated client context that future crypto operations can reuse.
`POST /api/v1/operations/authorize` remains the low-level alias/policy check.
`POST /api/v1/operations/sign`, `verify`, and `random` reuse that same authentication + authorization model and keep the public contract stable and customer-facing: callers provide alias names, high-level algorithms such as `RS256` / `PS256` / `ES256` / `HS256`, and base64 payloads instead of raw PKCS#11 device/slot/handle details.

## Intentionally out of scope for this issue

This scaffold still does **not** yet add:

- broader crypto contracts such as encrypt/decrypt/wrap/unwrap or key metadata lookup
- OAuth/OIDC or broader external authn/authz protocol handling beyond the first shared API-key slice
- tenant routing / portal concepts / edge orchestration
- durable job/workflow processing state
- a customer self-service portal or duplicated operator UI inside the API host

Those can land incrementally once the machine-facing contract expands.
