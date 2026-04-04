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

- `admin` - a lab-flavored admin-panel image that preserves the existing container runtime contract for local use:
  - `AdminStorage__DataRoot=/var/lib/pkcs11wrapper-admin`
  - `CryptoApiSharedPersistence__ConnectionString=Data Source=/var/lib/pkcs11wrapper-cryptoapi/shared-state.db`
  - `AdminRuntime__DisableHttpsRedirection=true`
  - built-in `/health/live` and `/health/ready` endpoints plus a compose healthcheck wired to the readiness probe
  - SoftHSM module exposed at `/opt/pkcs11/lib/libsofthsm2.so`
- `softhsm` - a utility/backend container that owns the shared SoftHSM config/token store and can seed or reset the token with `softhsm2-util` + `pkcs11-tool`

The services use two named volumes for shared state:

- `/opt/pkcs11/softhsm` keeps the SoftHSM config/token store shared between `softhsm` and `admin`
- `/var/lib/pkcs11wrapper-cryptoapi` keeps the local/dev shared SQLite control-plane database used by the admin panel's **Crypto API Access** workflow

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

The **Crypto API Access** page should be usable immediately after sign-in; this compose bundle intentionally stays on a local shared SQLite database for lab use and auto-initializes its schema on first use.

Default values from `.env.example`:

- admin user: `admin`
- admin password: `ChangeMe!123456`
- SoftHSM token label: `Pkcs11Wrapper CI Token`
- SoftHSM user PIN: `123456`
- SoftHSM SO PIN: `12345678`
- seeded AES key: `ci-aes` (`A1`)
- seeded RSA keypair: `ci-rsa` (`B2`)

Those SoftHSM defaults intentionally match the repository's existing fixture conventions so local demos and troubleshooting line up with `eng/setup-softhsm-fixture.sh` and the current docs.

## First-run behavior

On first `docker compose up`:

1. the `softhsm` service creates `/opt/pkcs11/softhsm/softhsm2.conf` in the named volume
2. if `SOFTHSM_AUTO_SEED=1` (default), it initializes the token if the configured label is missing
3. it seeds one AES-256 secret key and one RSA-2048 keypair if they do not already exist
4. the `admin` service seeds the bootstrap device profile pointing to `/opt/pkcs11/lib/libsofthsm2.so` and the configured token label
5. the `admin` service auto-initializes the local shared Crypto API control-plane database at `/var/lib/pkcs11wrapper-cryptoapi/shared-state.db`
6. the admin panel persists its own runtime state under `/var/lib/pkcs11wrapper-admin`

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
- Rotate the bootstrap admin password from the `Users` page after first sign-in if the stack will live longer than a quick demo.
- The `admin-data` volume includes the bootstrap notice, local users, Data Protection keys, device profiles, telemetry retention files, audit log, lab templates, and protected PIN cache.
- The `cryptoapi-shared-state` volume contains the local/dev shared SQLite database that powers the admin panel's Crypto API Access control-plane workflow. Production-oriented multi-instance deployments can switch the same control plane to `Provider=Postgres` instead.
- The SoftHSM lab state lives entirely in the `softhsm-state` named volume; deleting that volume resets the token/config.
- For persistent non-lab container deployments, back up and preserve the admin data volume intentionally rather than treating this compose bundle as the long-term deployment model.
