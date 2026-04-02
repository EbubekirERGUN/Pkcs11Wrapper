# Docker Compose SoftHSM lab stack

This bundle brings up a **local/dev/lab** stack for the admin panel plus a SoftHSM-backed PKCS#11 environment.

It is intentionally **not** a production orchestration recipe:

- no TLS termination
- no external secret manager
- bootstrap credentials live in the compose env file unless you override them
- SoftHSM state is a local named volume meant for demos, smoke-style checks, onboarding, and lab work

## What the stack includes

- `admin` - a lab-flavored admin-panel image that preserves the existing container runtime contract:
  - `AdminStorage__DataRoot=/var/lib/pkcs11wrapper-admin`
  - `AdminRuntime__DisableHttpsRedirection=true`
  - SoftHSM module exposed at `/opt/pkcs11/lib/libsofthsm2.so`
- `softhsm` - a utility/backend container that owns the shared SoftHSM config/token store and can seed or reset the token with `softhsm2-util` + `pkcs11-tool`

The two services share a named volume mounted at `/opt/pkcs11/softhsm`. The admin panel points `SOFTHSM2_CONF` at that shared config, so the in-container SoftHSM library sees the same token store as the helper container.

## Quick start

```bash
cd deploy/compose/softhsm-lab
cp .env.example .env
# edit .env if you want different admin credentials, token label, or PINs

docker compose up --build -d
```

Then open <http://localhost:8080> and sign in with the bootstrap admin credential from `.env`.

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
5. the admin panel persists its own runtime state under `/var/lib/pkcs11wrapper-admin`

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
- Rotate the bootstrap admin password from the `Users` page after first sign-in if the stack will live longer than a quick demo.
- The `admin-data` volume includes the bootstrap notice, local users, Data Protection keys, device profiles, telemetry retention files, audit log, lab templates, and protected PIN cache.
- The SoftHSM lab state lives entirely in the `softhsm-state` named volume; deleting that volume resets the token/config.
