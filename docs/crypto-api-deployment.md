# Single-dashboard + multi-instance Crypto API deployment

This guide documents the **current supported operating model** for the repository's admin/dashboard and Crypto API projects:

> **one admin dashboard + many stateless Crypto API instances**

Keep this guide operator-focused:

- where state lives
- what each component owns
- how to scale the Crypto API without turning it into a per-node snowflake
- what to mount or persist in containerized deployments
- what is deliberately **not** provided by the repo yet

For host/API surface details, see [docs/crypto-api-host.md](docs/crypto-api-host.md).
For the standalone admin image contract, see [docs/admin-container.md](docs/admin-container.md).

## What the current topology is

```mermaid
flowchart LR
    O[Operators] --> A[Pkcs11Wrapper.Admin.Web\nsingle admin dashboard]
    A --> AR[(AdminStorage__DataRoot\nusers, audit log, telemetry,\ndevice profiles, protected pins,\nData Protection keys)]
    A -->|CryptoApiSharedPersistence| S[(Shared Crypto API state\nSQLite database)]

    G[Gateway / load balancer] --> C1[Crypto API instance A]
    G --> C2[Crypto API instance B]
    G --> CN[Crypto API instance N]

    C1 -->|authn/authz + last-used metadata| S
    C2 -->|authn/authz + last-used metadata| S
    CN -->|authn/authz + last-used metadata| S

    C1 --> H[(PKCS#11 module / HSM)]
    C2 --> H
    CN --> H
```

Operationally:

- run **one** `Pkcs11Wrapper.Admin.Web` instance per deployment boundary
- run **one or more** `Pkcs11Wrapper.CryptoApi` instances behind your gateway/load balancer
- point the admin dashboard and every Crypto API instance at the **same** `CryptoApiSharedPersistence:ConnectionString`
- keep the admin dashboard's own storage root **separate** from the shared Crypto API state database

## Responsibilities by component

### `Pkcs11Wrapper.Admin.Web` owns operator workflows

The admin dashboard is the operator-facing boundary.

It owns:

- local admin sign-in and cookies
- admin user records
- append-only audit log
- admin-side PKCS#11 telemetry retention/export files
- device profiles
- protected PIN storage
- lab templates
- ASP.NET Core Data Protection keys

That mutable app state lives under `AdminStorage__DataRoot`.
In container deployments, the repository image defaults that to `/var/lib/pkcs11wrapper-admin`.
When the dashboard is also configured with `CryptoApiSharedPersistence`, its **Crypto API Access** workflow operates against the same shared client/key control-plane data consumed by the API instances.

Treat this as **admin-local state**, not as the shared multi-instance Crypto API database.

### `Pkcs11Wrapper.CryptoApi` owns machine-facing request handling

The Crypto API host is intentionally thin.

It owns:

- HTTP request handling for machine clients
- API-key authentication against the shared store
- alias/policy authorization against the shared store
- request-time PKCS#11 execution using the configured module path and optional user PIN
- health endpoints for process liveness and runtime readiness

It does **not** own:

- a local operator UI
- a node-local JSON control-plane database
- per-instance client/key/policy state
- sticky-session requirements

Each instance is meant to be replaceable.

### The shared persistence store owns control-plane state that cannot stay per-node

When `CryptoApiSharedPersistence:ConnectionString` is configured, the shared store keeps the state that every API instance must agree on:

- API clients/applications
- API keys and hashed secrets
- key aliases
- policy documents
- client-to-policy bindings
- alias-to-policy bindings
- API-key last-used metadata

This is the state that allows multiple Crypto API instances to authenticate and authorize consistently.

## What the admin dashboard and Crypto API share safely

The dashboard and the API do **not** share all runtime state.
They share only the **Crypto API control-plane state** configured through `CryptoApiSharedPersistence`.

### Shared between dashboard and API

When both point at the same `CryptoApiSharedPersistence:ConnectionString`, they share:

- API clients/applications
- generated API-key identifiers plus hashed secret records
- alias definitions
- policy definitions
- binding relationships
- usage metadata such as `last_used_at_utc`

### Not shared

The following stay admin-local and should **not** be treated as Crypto API shared state:

- `AdminStorage__DataRoot`
- admin user store
- admin audit log
- admin telemetry files
- protected PIN cache
- Data Protection key ring
- admin cookies/session material

That separation is deliberate: the admin dashboard remains an operator console, while the Crypto API remains a stateless machine-facing boundary.

### Why the shared store is safe enough for the current model

The current store implementation prepares every SQLite connection with:

- `PRAGMA foreign_keys = ON`
- `PRAGMA busy_timeout = 5000`
- `PRAGMA journal_mode = WAL`

And it keeps the control-plane schema normalized into separate client, key, alias, policy, and binding tables.
Binding replacement flows run transactionally.

Operator implications:

- multiple independent processes can coordinate through the same database file when the underlying storage really supports SQLite locking/WAL semantics
- API secrets are **not** stored in plaintext; the repo persists hashed secret material and only reveals the generated secret once at creation time
- the admin dashboard can manage the same shared client/key state without becoming the runtime for machine traffic

## Recommended filesystem and state layout

Even on a single host, keep these storage concerns distinct:

```text
/srv/pkcs11wrapper/
  admin-data/              # AdminStorage__DataRoot
  cryptoapi-shared/
    shared-state.db        # CryptoApiSharedPersistence database
  pkcs11-client/           # mounted vendor PKCS#11 libraries / client bundle
  vendor-state/            # only if the vendor client truly requires writable side files
```

Prefer this separation over dropping the shared SQLite file inside the admin storage root.
It makes backup, restore, and responsibility boundaries much clearer.

## Configuration recipe

### Admin dashboard

Keep the admin dashboard's own storage root, and add the shared Crypto API connection string:

```text
AdminStorage__DataRoot=/srv/pkcs11wrapper/admin-data
CryptoApiSharedPersistence__Provider=Sqlite
CryptoApiSharedPersistence__ConnectionString=Data Source=/srv/pkcs11wrapper/cryptoapi-shared/shared-state.db
CryptoApiSharedPersistence__AutoInitialize=true
```

### Every Crypto API instance

Point every instance at the **same** shared persistence target and the same PKCS#11 client layout:

```text
CryptoApiHost__ApiBasePath=/api/v1
CryptoApiRuntime__ModulePath=/srv/pkcs11wrapper/pkcs11-client/libvendorpkcs11.so
CryptoApiRuntime__UserPin=<secret>
CryptoApiRuntime__DisableHttpsRedirection=true
CryptoApiSharedPersistence__Provider=Sqlite
CryptoApiSharedPersistence__ConnectionString=Data Source=/srv/pkcs11wrapper/cryptoapi-shared/shared-state.db
CryptoApiSharedPersistence__AutoInitialize=true
```

Important:

- `ModulePath` must be the path the process/container can actually open
- `UserPin` is deployment secret material; do not hard-code it in checked-in config
- `AutoInitialize=true` is fine for first-run convenience; the schema creation path is designed to be idempotent

## Scaling expectations for the stateless Crypto API service

The Crypto API service is stateless in the **instance** sense, not in the "nothing external exists" sense.

### What horizontal scaling does help with

Adding more API instances helps with:

- HTTP connection handling
- request parsing/serialization
- concurrent authentication and authorization work
- reducing the blast radius of a single process crash or restart
- rolling upgrades behind a gateway/load balancer

You do **not** need sticky sessions for the current request model.
A request can land on any healthy Crypto API instance as long as that instance can:

- reach the same shared control-plane database
- load the same PKCS#11 module/client libraries
- reach the same HSM/token environment

### What horizontal scaling does **not** guarantee

Adding more API instances does **not** mean infinite HSM throughput.
The current runtime still opens PKCS#11 module/session state per operation path and is ultimately bounded by:

- HSM session limits
- token login behavior
- vendor-side concurrency characteristics
- key lookup cost
- network latency to the HSM or vendor client stack
- license/appliance limits from the PKCS#11 vendor

Treat scale-out as a way to add **stateless HTTP workers**, not as proof that the HSM tier can absorb unlimited parallelism.

### Practical operator sizing guidance

Before increasing instance count aggressively, verify:

- how many concurrent sessions the HSM/token can sustain
- whether the vendor client or appliance has per-host or per-cluster connection limits
- whether your sign/verify/random mix is CPU-bound in ASP.NET or device-bound in the HSM
- whether the configured key aliases resolve uniquely and consistently

A good pattern is:

1. start with one API instance
2. validate steady-state sign/verify/random traffic
3. add a second instance
4. observe HSM/session behavior, readiness stability, and latency tails
5. scale further only when the external PKCS#11 tier proves it can handle the load

## Current routing/alias expectations

Today, alias records in shared state can carry:

- `device_route`
- `slot_id`
- `object_label`
- `object_id_hex`

For current runtime execution, the Crypto API operation path requires the PKCS#11 details that actually resolve a key in the local module context:

- `slot_id`
- `object_label` and/or `object_id_hex`

`device_route` is useful shared control-plane metadata, but the current in-process execution path does **not** use it as an external service-discovery hop.
Do not build an operator assumption that `device_route` alone steers requests to different API pools.

## Health, readiness, and rollout behavior

### Admin dashboard

- `/health/live` checks process liveness
- `/health/ready` checks admin storage-root and writable runtime directories

That readiness probe tells you whether the admin app can use its own storage, **not** whether the Crypto API/HSM tier is ready.

### Crypto API

- `/health/live` checks process liveness
- `/health/ready` checks:
  - whether the configured PKCS#11 module can be loaded
  - whether shared persistence is reachable when it is configured

Use the Crypto API readiness endpoint as your load-balancer target gate.
An instance should not receive traffic if it cannot load the PKCS#11 module or open the configured shared store.

## Container and Docker guidance

### What the repo already provides

Today the repository ships:

- a supported admin dashboard Dockerfile at `src/Pkcs11Wrapper.Admin.Web/Dockerfile`
- an admin env template at `deploy/container/admin-panel.env.example`
- a local/dev SoftHSM compose lab at `deploy/compose/softhsm-lab`

### What the repo does **not** provide yet

Today the repository does **not** ship:

- a supported `Pkcs11Wrapper.CryptoApi` Dockerfile
- a production compose/Kubernetes manifest for the multi-instance Crypto API service
- a non-SQLite shared persistence provider

So for Crypto API containers, the image/wrapper is currently **operator-owned**.
Base it on `src/Pkcs11Wrapper.CryptoApi`, but preserve the runtime contract described here.

A starting env template for that operator-owned container/process wrapper lives at:

- `deploy/container/crypto-api.env.example`

### Container rules that matter

For the admin dashboard container:

- use the repository Dockerfile directly
- persist `AdminStorage__DataRoot`
- mount PKCS#11 libraries read-only
- keep the admin surface behind a trusted boundary

For every Crypto API container you build around the host project:

- inject the same `CryptoApiSharedPersistence__ConnectionString`
- inject the same `CryptoApiRuntime__ModulePath` convention and make that path real inside the container
- inject `CryptoApiRuntime__UserPin` through your secret manager/orchestrator, not by baking it into the image
- wire `/health/ready` into the scheduler/load balancer
- keep container-local state disposable

### Recommended container volume model

A practical split is:

- one persistent volume for the admin dashboard data root
- one persistent/shared volume for the Crypto API SQLite database file
- one read-only mount for PKCS#11 client libraries
- one separate writable vendor-state mount only if the vendor client requires it

Do **not** collapse everything into one writable directory just because containers make that easy.

### Multi-host caution with SQLite

The current shared-state provider is SQLite.
That works well for small-to-medium deployments **only when** every process sees storage with correct SQLite file-locking and WAL behavior.

If you cannot guarantee that for your shared volume/filesystem:

- keep the admin dashboard and Crypto API instances on a topology with trustworthy shared storage semantics
- or keep Crypto API scale-out on a single host until a server-grade shared backend lands

Do not assume every network filesystem is automatically safe for SQLite WAL.

## Safe rollout pattern

For upgrades or new deployments:

1. bring up or upgrade the **single** admin dashboard with its existing `AdminStorage__DataRoot`
2. verify the dashboard can still open the shared Crypto API database
3. roll Crypto API instances behind the load balancer using the same shared connection string and PKCS#11 mount layout
4. watch `/health/ready` on each instance before shifting traffic
5. verify one authenticated request path such as `auth/self` or a low-risk sign/verify call

## Current constraints to plan around

The current deployment model is intentionally conservative.
Plan around these present-day constraints:

- one admin dashboard is the documented operating model
- Crypto API instances are stateless, but the shared control-plane state currently depends on SQLite
- the repository does not yet provide a first-class Crypto API container image
- the current admin UI now covers the practical shared-store workflow for clients, keys, aliases, policies, and bindings, but the overall control plane is still intentionally conservative
- current request execution depends on the locally configured PKCS#11 module path and HSM reachability on every API instance

If you need a larger multi-host topology with stronger shared-state guarantees, treat that as a future backend/infrastructure step rather than forcing the current SQLite-based control plane into a shape it does not yet claim to support.
