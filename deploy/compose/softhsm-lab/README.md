# Docker Compose SoftHSM lab stack

This bundle brings up a **local/dev/lab** stack for the admin panel plus a SoftHSM-backed PKCS#11 environment.

It is intentionally **not** a production orchestration recipe:

- no TLS termination
- no external secret manager
- bootstrap credentials live in the compose env file unless you override them
- SoftHSM state is a local named volume meant for demos, smoke-style checks, onboarding, and lab work

If you need the **standalone container deployment** path for the admin panel, use:

- `docs/admin-container.md`
- `deploy/container/admin-panel.env.example`

## What the stack includes

- `postgres` - the lab's shared control-plane database for Crypto API clients, keys, aliases, policies, and bindings
- `admin` - a lab-flavored admin-panel image that preserves the existing container runtime contract for local use:
  - `AdminStorage__DataRoot=/var/lib/pkcs11wrapper-admin`
  - `CryptoApiSharedPersistence__ConnectionString=Host=postgres;Port=5432;...`
  - `AdminRuntime__DisableHttpsRedirection=true`
  - built-in `/health/live` and `/health/ready` endpoints plus a compose healthcheck wired to the readiness probe
  - SoftHSM module exposed at `/opt/pkcs11/lib/libsofthsm2.so`
- `softhsm` - a utility/backend container that owns the shared SoftHSM config/token store and can seed or reset the token with `softhsm2-util` + `pkcs11-tool`

The services use three named volumes for shared state:

- `postgres-data` keeps the PostgreSQL control-plane database used by the admin panel's **Crypto API Access** workflow
- `/opt/pkcs11/softhsm` keeps the SoftHSM config/token store shared between `softhsm` and `admin`
- `admin-data` keeps the admin panel's own local runtime state

The admin panel points `SOFTHSM2_CONF` at the shared SoftHSM config, so the in-container library sees the same token store as the helper container.

## Quick start

```bash
cd deploy/compose/softhsm-lab
cp .env.example .env
# edit .env if you want different admin credentials, token label, or PINs

docker compose up --build -d
```

You can optionally confirm both services reached a healthy state with:

```bash
docker compose ps
```

Then open <http://localhost:8080> and sign in with the bootstrap admin credential from `.env`.

The **Crypto API Access** page should be usable immediately after sign-in; this compose bundle intentionally uses the same PostgreSQL-backed shared state model recommended for multi-instance Crypto API deployments, while keeping Redis optional and out of the authority path.

Default values from `.env.example`:

- admin user: `admin`
- admin password: `ChangeMe!123456`
- Postgres database: `pkcs11wrapper_cryptoapi`
- Postgres user: `cryptoapi`
- SoftHSM token label: `Pkcs11Wrapper CI Token`
- SoftHSM user PIN: `123456`
- SoftHSM SO PIN: `12345678`
- seeded AES key: `ci-aes` (`A1`)
- seeded RSA keypair: `ci-rsa` (`B2`)

Those SoftHSM defaults intentionally match the repository's existing fixture conventions so local demos and troubleshooting line up with `eng/setup-softhsm-fixture.sh` and the current docs.

## First-run behavior

On first `docker compose up`:

1. the `postgres` service initializes the `pkcs11wrapper_cryptoapi` lab database in the `postgres-data` volume
2. the `softhsm` service creates `/opt/pkcs11/softhsm/softhsm2.conf` in the named volume
3. if `SOFTHSM_AUTO_SEED=1` (default), it initializes the token if the configured label is missing
4. it seeds one AES-256 secret key and one RSA-2048 keypair if they do not already exist
5. the `admin` service seeds the bootstrap device profile pointing to `/opt/pkcs11/lib/libsofthsm2.so` and the configured token label
6. the `admin` service auto-initializes the shared Crypto API PostgreSQL schema on first use
7. the admin panel persists its own runtime state under `/var/lib/pkcs11wrapper-admin`

The admin device seed follows the app's current behavior: it only applies when the admin data volume is empty. Once `device-profiles.json` exists, later env changes do not overwrite persisted device profiles.

## Useful commands

Show current lab objects:

```bash
docker compose exec softhsm show-objects
```

Re-seed only if the token is currently missing:

```bash
docker compose exec softhsm seed-token --if-missing
```

Reset the SoftHSM lab token store and recreate the seeded objects:

```bash
docker compose exec softhsm seed-token --reset
```

Stop the stack:

```bash
docker compose down
```

Remove the stack plus the persisted admin and SoftHSM volumes:

```bash
docker compose down -v
```

## Notes and limitations

- This stack is for **local/dev/lab** usage only.
- The admin service still runs without HTTPS redirection, by design, to stay friction-free for local compose use.
- The admin service now reports healthy only after its storage-backed readiness probe succeeds, which makes startup status easier to understand from `docker compose ps`.
- PostgreSQL is the only supported shared persistence backend for the Crypto API control plane; Redis remains optional acceleration only and is not part of this compose stack.
- Rotate the bootstrap admin password from the `Users` page after first sign-in if the stack will live longer than a quick demo.
- The `admin-data` volume includes the bootstrap notice, local users, Data Protection keys, device profiles, telemetry retention files, audit log, lab templates, and protected PIN cache.
- The `postgres-data` volume contains the PostgreSQL database that powers the admin panel's Crypto API Access control-plane workflow and matches the supported shared-state backend for local/dev/lab and production-oriented deployments.
- The SoftHSM lab state lives entirely in the `softhsm-state` named volume; deleting that volume resets the token/config.
- For persistent non-lab container deployments, back up and preserve the admin data volume intentionally rather than treating this compose bundle as the long-term deployment model.
