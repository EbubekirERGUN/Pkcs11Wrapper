# Crypto API host scaffold

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
  - no local durable application state
  - intended to scale out as **many stateless instances** behind a load balancer or gateway

That separation keeps the product model simple for now:

> one admin dashboard + many stateless crypto API instances

The admin app remains the place for operations and governance. The crypto API host becomes the place for future request/response signing, verification, encryption, decryption, wrapping, and key-resolution workflows.

## Current scaffold contents

The first slice is deliberately small but real:

- dedicated `src/Pkcs11Wrapper.CryptoApi` project in the solution
- ASP.NET Core host with DI + configuration binding
- service document at `/`
- versioned route group rooted at `/api/v1`
- runtime descriptor endpoint at `/api/v1/runtime`
- explicit future operation namespace at `/api/v1/operations`
- liveness endpoint at `/health/live`
- readiness endpoint at `/health/ready`
- readiness check that attempts to load the configured PKCS#11 module via `Pkcs11Module.Load(...)`
- dedicated test project for base-path normalization, runtime descriptor behavior, and readiness health behavior

## Runtime model

The host is designed around a **stateless request pipeline**:

- no host-local portal/session state
- no local JSON database or app data root
- no operator identity system in this first slice
- each instance should be replaceable without data migration
- environment/config drives module selection and network exposure

This keeps the API host suitable for future multi-instance deployment while avoiding premature tenant, edge, or portal abstractions.

## Configuration

Current settings live under two sections:

```json
{
  "CryptoApiHost": {
    "ServiceName": "Pkcs11Wrapper.CryptoApi",
    "ApiBasePath": "/api/v1"
  },
  "CryptoApiRuntime": {
    "DisableHttpsRedirection": false,
    "ModulePath": "/usr/lib/libsofthsm2.so"
  }
}
```

Notes:

- `CryptoApiHost:ApiBasePath` defines where future machine-facing routes will live.
- `CryptoApiRuntime:ModulePath` is required for readiness because the host is not actually ready to serve crypto traffic until it can load a PKCS#11 module.
- `CryptoApiRuntime:DisableHttpsRedirection=true` is useful for local/container smoke flows behind a trusted reverse proxy or local HTTP test loop.

## Local run example

```bash
cd src/Pkcs11Wrapper.CryptoApi
export CryptoApiRuntime__ModulePath=/usr/lib/libsofthsm2.so
export CryptoApiRuntime__DisableHttpsRedirection=true
dotnet run
```

Useful endpoints:

- `/`
- `/health/live`
- `/health/ready`
- `/api/v1`
- `/api/v1/runtime`
- `/api/v1/operations`

## Intentionally out of scope for this issue

This scaffold does **not** yet add:

- concrete sign/verify/encrypt/decrypt request contracts
- external authn/authz or API gateway policy
- tenant routing / portal concepts / edge orchestration
- durable job state or workflow storage
- admin-dashboard features duplicated into the API host

Those can land incrementally once the machine-facing contract is defined.
