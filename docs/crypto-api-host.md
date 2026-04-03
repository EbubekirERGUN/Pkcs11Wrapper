# Crypto API host scaffold + API key lifecycle slice

`Pkcs11Wrapper.CryptoApi` is the first machine-facing service host for the repository.

It is intentionally **thin** and intentionally **separate** from the admin dashboard stack.

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

The admin app remains the place for operations and governance. The crypto API host becomes the place for future request/response signing, verification, encryption, decryption, wrapping, and key-resolution workflows.

## Current scaffold contents

The current slice is still deliberately small, but now includes the first practical API client / API key lifecycle foundation for future multi-instance deployments:

- dedicated `src/Pkcs11Wrapper.CryptoApi` project in the solution
- ASP.NET Core host with DI + configuration binding
- service document at `/`
- versioned route group rooted at `/api/v1`
- runtime descriptor endpoint at `/api/v1/runtime`
- explicit future operation namespace at `/api/v1/operations`
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
- admin control-plane scaffolding in `Pkcs11Wrapper.Admin.Web` via the **Crypto API Access** page when it is configured against the same shared store
- dedicated test project covering base-path normalization, runtime descriptor metadata, readiness health behavior, shared-state round-tripping, lifecycle management, and schema migration behavior

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
  - stable alias name used by future API requests
  - slot/object-resolution metadata (`slot_id`, label, object-id hex)
- **Policies**
  - versioned JSON policy document payload
  - enable/disable state
- **Bindings**
  - client → policy
  - alias → policy

That gives the repo a concrete place to keep future request authentication, alias resolution, and policy enforcement inputs outside any single node.

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
    "ModulePath": "/usr/lib/libsofthsm2.so"
  },
  "CryptoApiSharedPersistence": {
    "Provider": "Sqlite",
    "ConnectionString": "Data Source=/srv/pkcs11wrapper-cryptoapi/shared-state.db",
    "AutoInitialize": true
  }
}
```

Notes:

- `CryptoApiHost:ApiBasePath` defines where future machine-facing routes will live.
- `CryptoApiRuntime:ModulePath` is required for readiness because the host is not actually ready to serve crypto traffic until it can load a PKCS#11 module.
- `CryptoApiRuntime:DisableHttpsRedirection=true` is useful for local/container smoke flows behind a trusted reverse proxy or local HTTP test loop.
- `CryptoApiSharedPersistence:Provider` currently supports only `Sqlite`.
- `CryptoApiSharedPersistence:ConnectionString` enables the shared state store. If omitted, the host still runs, but `/api/v1/shared-state` reports that shared persistence is not configured.
- `CryptoApiSharedPersistence:AutoInitialize=true` creates the schema on startup/first use.
- The admin panel can point at the same `CryptoApiSharedPersistence` section to manage shared clients and keys from the **Crypto API Access** page.

## Local run example

```bash
cd src/Pkcs11Wrapper.CryptoApi
export CryptoApiRuntime__ModulePath=/usr/lib/libsofthsm2.so
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

`/api/v1/shared-state` returns provider/schema/count metadata when the shared store is configured and available.
`/api/v1/auth/self` is the first practical authentication slice: it validates the hashed shared secret, enforces disabled / revoked / expired state, updates last-used metadata, and returns the authenticated client context that future crypto operations can reuse.

## Intentionally out of scope for this issue

This scaffold still does **not** yet add:

- concrete sign/verify/encrypt/decrypt request contracts
- OAuth/OIDC or broader external authn/authz protocol handling beyond the first shared API-key slice
- tenant routing / portal concepts / edge orchestration
- durable job/workflow processing state
- a customer self-service portal or duplicated operator UI inside the API host

Those can land incrementally once the machine-facing contract is defined.
