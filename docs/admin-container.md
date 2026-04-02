# Admin panel container deployment

This guide covers the **standalone container deployment** story for the `Pkcs11Wrapper` admin panel.

It builds on the repository's existing container image at `src/Pkcs11Wrapper.Admin.Web/Dockerfile` and the existing **local/dev/lab** SoftHSM compose bundle under `deploy/compose/softhsm-lab`, but keeps the focus on the operational questions a real container deployment needs answered:

- which environment variables matter
- what must be persisted
- where telemetry/audit/bootstrap data lives
- how PKCS#11 libraries should be mounted into the container
- which parts are safe for local/dev only versus longer-lived deployments

## Pick the right deployment path

Use the path that matches your goal:

| Scenario | Recommended path | Notes |
| --- | --- | --- |
| Local source-tree development | `cd src/Pkcs11Wrapper.Admin.Web && dotnet run` | Uses `App_Data` by default when not running in a container. |
| Single-container admin deployment | `src/Pkcs11Wrapper.Admin.Web/Dockerfile` | The main image expects external persistence and operator-supplied PKCS#11 mounts. |
| Reproducible local/dev/lab stack with SoftHSM | `deploy/compose/softhsm-lab` | Includes a lab-flavored admin image plus a helper SoftHSM container. Not a production recipe. |

The main admin image and the compose lab are related, but they are **not** the same thing:

- the main image does **not** bundle vendor PKCS#11 client libraries for you
- the main image does **not** bundle production TLS termination/cert handling
- the compose lab intentionally adds SoftHSM tooling so local demos and troubleshooting stay friction-free

If you only need a safe local sandbox, use the compose lab.
If you need to run the admin panel as a real containerized app, use the main image and the guidance below.

## Build the image

From the repository root:

```bash
docker build -f src/Pkcs11Wrapper.Admin.Web/Dockerfile -t pkcs11wrapper-admin .
```

## Default runtime contract

The main image sets these defaults:

- `ASPNETCORE_URLS=http://+:8080`
- `ASPNETCORE_HTTP_PORTS=8080`
- `DOTNET_RUNNING_IN_CONTAINER=true`
- `DOTNET_EnableDiagnostics=0`
- `AdminStorage__DataRoot=/var/lib/pkcs11wrapper-admin`
- `AdminRuntime__DisableHttpsRedirection=true`
- `HOME=/var/lib/pkcs11wrapper-admin/home`
- `TMPDIR=/var/lib/pkcs11wrapper-admin/tmp`

The image also creates:

- `/var/lib/pkcs11wrapper-admin` - default persisted admin data root
- `/var/lib/pkcs11wrapper-admin/keys` - ASP.NET Core Data Protection key ring location
- `/var/lib/pkcs11wrapper-admin/home` - explicit writable home directory for non-root runtime helpers
- `/var/lib/pkcs11wrapper-admin/tmp` - explicit writable temp path so the app can stay compatible with read-only root filesystem deployments
- `/opt/pkcs11/lib` - convenient mount point for PKCS#11 modules/client libraries

The container runs as non-root UID `64198` by default.

## Built-in health endpoints and container healthcheck

The admin image now exposes two unauthenticated health endpoints:

- `/health/live` - lightweight liveness probe for process availability
- `/health/ready` - readiness probe that verifies the admin storage root plus the app's writable runtime directories are present and writable

The image also bakes in a Docker `HEALTHCHECK` that probes `http://127.0.0.1:8080/health/ready` from inside the container, so a plain `docker ps` / `docker inspect` workflow can see whether the container is healthy without extra operator wiring.

Operationally, this is meant to catch practical container problems such as:

- mounted admin storage that is missing or no longer writable
- read-only or permission-broken runtime writable paths
- an app process that is up but not actually ready to serve requests

The readiness check is intentionally **storage-focused** and low-risk. It does **not** attempt to prove that a specific HSM is online or that every configured PKCS#11 module is reachable, because those concerns can legitimately vary across operators, maintenance windows, and device states.

## Environment template

A starter env template for the standalone container path lives at:

- `deploy/container/admin-panel.env.example`

Copy it to an operator-controlled location, edit it, then pass it to `docker run --env-file ...` or your orchestrator's equivalent.

Example:

```bash
cp deploy/container/admin-panel.env.example /etc/pkcs11wrapper/admin-panel.env
# edit /etc/pkcs11wrapper/admin-panel.env
```

## First-run bootstrap behavior

The bootstrap environment variables are intentionally **first-run seeds**, not ongoing configuration management.

### Bootstrap admin user

`LocalAdminBootstrap__UserName` and `LocalAdminBootstrap__Password` are used only when the admin user store does not exist yet.

On first successful seed, the app writes:

- `admin-users.json`
- `bootstrap-admin.txt`

under the configured storage root.

Important behavior:

- if you leave `LocalAdminBootstrap__Password` empty, the app generates a password and writes it to `bootstrap-admin.txt`
- once `admin-users.json` already exists, changing the env vars later does **not** rotate existing credentials
- after first sign-in, rotate the bootstrap password from the UI and retire `bootstrap-admin.txt`

### Bootstrap device profile

`AdminBootstrapDevice__*` values behave the same way for the first device profile.

Important behavior:

- seeding happens only when no device profiles exist yet
- `AdminBootstrapDevice__ModulePath` must be the **in-container path**, not the host path
- once `device-profiles.json` exists, later env changes do **not** overwrite persisted device profiles

That design prevents accidental data loss on restart, but it also means env changes are **not** a substitute for normal admin operations once the volume is already initialized.

## What must be persisted

For container deployments, the real unit of state is the admin storage root:

- `/var/lib/pkcs11wrapper-admin` by default
- or whatever you set through `AdminStorage__DataRoot`

Persist that path with a Docker named volume or a carefully permissioned bind mount.

### Storage-root contents

The admin panel writes its mutable state under the storage root.

Typical files/directories include:

| Path under storage root | Purpose |
| --- | --- |
| `admin-users.json` | local admin user database |
| `bootstrap-admin.txt` | first-run plaintext bootstrap notice |
| `device-profiles.json` | saved PKCS#11 device profiles |
| `audit-log.jsonl` | append-only chained audit log |
| `audit-log.jsonl.bak` | crash-safe replacement backup of the current audit file when applicable |
| `pkcs11-telemetry.jsonl` | active redacted PKCS#11 telemetry log |
| `pkcs11-telemetry-*.jsonl` | rotated telemetry archives |
| `lab-templates.json` | saved PKCS#11 Lab templates |
| `protected-pins.json` | locally protected cached PIN metadata/storage |
| `keys/` | ASP.NET Core Data Protection key ring |
| `home/` | explicit writable non-root home directory used by the container runtime when needed |
| `tmp/` | explicit writable temp directory used by readiness checks and runtime temporary files |
| `*.bak` companions for JSON files | crash-safe replacement backups kept during atomic writes |

Operationally, this means the storage-root volume is where these concerns live together:

- local users
- bootstrap notice file
- device profiles
- audit history
- PKCS#11 telemetry retention
- saved lab templates
- protected PIN cache
- Data Protection keys

### Volume layout at a glance

Use a layout like this as your mental model:

| Container path | Persist? | Purpose | Recommended strategy |
| --- | --- | --- | --- |
| `/var/lib/pkcs11wrapper-admin` | Yes | admin app state | named volume or bind mount |
| `/opt/pkcs11/lib` | Usually yes as host input | PKCS#11 shared libraries/client bundle | bind mount read-only from host |
| vendor-specific writable client path | If vendor requires it | vendor cache/config/runtime state | separate dedicated mount, not inside admin data root |
| `/opt/pkcs11/softhsm` | Only for the compose lab | shared SoftHSM token/config state | lab-only named volume |

A practical host-side layout often looks like this:

```text
/srv/pkcs11wrapper-admin/
  env/
    admin-panel.env
  data/
  pkcs11-client/
  vendor-state/   # only if the vendor library truly requires writable side files
```

One possible mapping would then be:

- `/srv/pkcs11wrapper-admin/data -> /var/lib/pkcs11wrapper-admin`
- `/srv/pkcs11wrapper-admin/pkcs11-client -> /opt/pkcs11/lib:ro`
- `/srv/pkcs11wrapper-admin/vendor-state -> <vendor-required writable path>`

Do **not** mix vendor-client writable runtime files into the admin storage root unless you intentionally want those lifecycle concerns tied together.

## Example: standalone container run

This example uses:

- a persistent named volume for admin state
- a read-only bind mount for PKCS#11 libraries
- an env file for first-run bootstrap/device settings
- low-risk hardening flags that fit the current image contract

```bash
docker run --rm \
  --name pkcs11wrapper-admin \
  -p 8080:8080 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --env-file /etc/pkcs11wrapper/admin-panel.env \
  -v pkcs11wrapper-admin-data:/var/lib/pkcs11wrapper-admin \
  -v /srv/pkcs11wrapper-admin/pkcs11-client:/opt/pkcs11/lib:ro \
  pkcs11wrapper-admin
```

Why these flags are practical here:

- `--read-only` works with the current image because the admin app's writable home/temp/key material is already redirected under the persisted storage root
- `--cap-drop ALL` removes Linux capabilities the app does not need for its normal HTTP + file-backed admin workflow
- `--security-opt no-new-privileges:true` prevents privilege escalation through executed child processes
- `--pids-limit 256` adds a simple guardrail against runaway process creation without getting orchestration-specific

If your vendor library requires additional writable client-side state, add a **separate** mount for that vendor path rather than making `/opt/pkcs11/lib` writable.

## PKCS#11 library and client mount patterns

The admin panel only knows how to load a PKCS#11 module from the path you configure. It does **not** automatically import host libraries into the container. You must make the required files visible inside the container yourself.

### Pattern 1: mount a single shared library

Good when the vendor ships one self-contained `.so` and its runtime dependencies are already present in the image or the base OS.

```bash
-v /usr/local/lib/vendor/libvendorpkcs11.so:/opt/pkcs11/lib/libvendorpkcs11.so:ro
```

Then set:

```text
AdminBootstrapDevice__ModulePath=/opt/pkcs11/lib/libvendorpkcs11.so
```

### Pattern 2: mount a whole client library directory

Good when the module depends on adjacent helper libraries/config files.

```bash
-v /opt/vendor/pkcs11-client:/opt/pkcs11/lib:ro
```

Then point the module path at the in-container library file inside that mounted directory.

### Pattern 3: mount a broader vendor client bundle

Some vendors expect a larger client install tree plus separate writable paths for logs/cache/runtime config. In that case:

- mount the immutable client binaries/config read-only
- mount any required writable vendor state separately
- keep the admin storage root separate from the vendor writable state

The key rule is simple:

> configure the app with the **container path it can actually open**, not the host path where the file originally lived.

## Permissions and non-root runtime behavior

The container runs as UID `64198`.

That has two important consequences:

1. the mounted admin data root must be writable by UID `64198` (or compatible through group permissions)
2. the mounted PKCS#11 library path only needs to be readable, so prefer `:ro`

### Easiest option: named volumes

Docker named volumes are usually the least painful option for `/var/lib/pkcs11wrapper-admin` because Docker manages ownership/permissions for the containerized workload.

### Bind-mount option

If you prefer a host bind mount, make sure the directory is writable by UID `64198` before first start.

Common approaches:

- pre-create the host directory and `chown` it to `64198`
- or align permissions so UID `64198` can write through a shared group policy on the host

Avoid running the container as root just to paper over filesystem ownership mistakes.

## Backup and restore guidance

### What counts as a real backup

A configuration export from the UI is useful, but it is **not** a full container-state backup.

A real backup for a container deployment should capture the mounted admin storage root because that is where the app keeps:

- users
- device profiles
- audit log
- telemetry files
- Data Protection keys
- protected PIN cache
- lab templates
- bootstrap notice file

If your PKCS#11 vendor/client setup also requires writable side files, back those up separately according to the vendor's own support model.

### Recommended backup posture

Before upgrades or host migration:

1. export device profiles from the `Configuration` page for a human-readable portability snapshot
2. take a filesystem/volume backup of the mounted admin storage root
3. preserve any vendor-required writable client state separately if you use it
4. treat the storage root and vendor client state as distinct restore units

If you can, stop or quiesce the admin container before taking the storage-root backup.

### Restore expectations

To restore onto a replacement container:

- mount the restored storage-root volume back at the same in-container path
- reapply the same PKCS#11 module/client mounts
- reapply any vendor-specific writable client mounts if used
- start the new container with the same or equivalent runtime env

If the `keys/` folder is missing or replaced, expect Data Protection-dependent features such as protected PIN storage and existing cookie/session material to stop lining up with the old host state.

## Upgrade guidance

Container upgrades should normally be **image replacement with the same mounted state**.

Typical safe pattern:

1. back up the storage root
2. pull/build the new image
3. stop the old container
4. start the new container with the same data volume and PKCS#11 mounts
5. verify sign-in, device visibility, and a basic read-only token operation

Remember:

- bootstrap env vars do not re-seed an already initialized storage root
- changing module-path env values does not overwrite persisted device profiles
- swapping images without preserving the storage-root volume creates a new empty admin instance

## Local/dev/lab versus production-safe guidance

The repository deliberately separates these two stories.

### Local/dev/lab

Use `deploy/compose/softhsm-lab` when you want:

- a disposable sandbox
- built-in SoftHSM availability
- known demo credentials/PINs
- reproducible local troubleshooting without vendor hardware

This stack is intentionally optimized for convenience:

- bootstrap credentials live in a compose env file
- SoftHSM state is just a local named volume
- HTTPS redirection stays disabled
- the bundle is designed for demos, onboarding, and validation, not public exposure

### Production-safe direction

For any longer-lived or higher-trust deployment, treat the current admin container as an **internal administrative surface** and tighten the environment around it.

Minimum practical guidance:

- keep the container behind a trusted reverse proxy or other private access boundary
- do not expose the raw HTTP listener broadly to the public internet
- rotate the bootstrap password immediately and retire the plaintext bootstrap notice file
- prefer operator-managed secrets/env injection over leaving example credentials in files
- persist and back up the storage root deliberately
- keep the built-in `/health/live` and `/health/ready` probes available to your local Docker or upstream monitoring path
- prefer `--read-only`, `--cap-drop ALL`, and `--security-opt no-new-privileges:true` when your runtime allows them
- mount PKCS#11 modules read-only whenever possible
- separate vendor-client writable state from admin app state
- understand that the current app auth model is local-user/cookie based, not external IdP/MFA/secret-vault integrated

If you need internet-facing exposure, centralized identity, MFA, or compliance-grade secret governance, plan additional infrastructure around the app rather than assuming the container alone provides that posture.

## Local/dev/lab compose stack

For the existing SoftHSM-backed lab stack:

```bash
cd deploy/compose/softhsm-lab
cp .env.example .env
# optional: edit .env

docker compose up --build -d
```

That bundle adds a lab-specific admin image plus a helper `softhsm` service and a shared `/opt/pkcs11/softhsm` volume so the admin panel and the helper see the same SoftHSM token store.

See:

- `deploy/compose/softhsm-lab/README.md`
- `deploy/compose/softhsm-lab/.env.example`

for the local/dev/lab workflow.
