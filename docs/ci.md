# CI

## Workflow

`.github/workflows/ci.yml` defines:

- `build-test-aot` (default SoftHSM lane)
- `vendor-regression` (optional non-SoftHSM lane, manual dispatch only)

Triggers:

- push to `main` and `master`
- all pull requests
- `workflow_dispatch` with optional vendor-lane inputs

Ordered steps:

- checkout the repository
- install the SDK pinned by `global.json`
- install native dependencies: `softhsm2`, `opensc`, `file`
- mark engineering scripts executable
- `dotnet restore Pkcs11Wrapper.sln`
- `dotnet build Pkcs11Wrapper.sln -c Release --no-restore`
- `./eng/run-regression-tests.sh`
- `./eng/run-smoke-aot.sh`

Job-level env:

- `DOTNET_NOLOGO=true`
- `DOTNET_CLI_TELEMETRY_OPTOUT=true`
- `CI=true`

## What CI guarantees

Regression coverage from `eng/run-regression-tests.sh` guarantees that:

- solution restore/build/test stays healthy on the pinned SDK
- the SoftHSM fixture contract is still valid
- the seeded AES and RSA objects are discoverable before tests start
- the xUnit suite still covers managed API shape, native layout assumptions, crypto flows, object lifecycle, and admin operations

Native AOT coverage from `eng/run-smoke-aot.sh` guarantees that:

- `samples/Pkcs11Wrapper.Smoke` still publishes as native AOT for `linux-x64`
- the published entrypoint exists and is executable
- the smoke binary still completes key runtime paths against the fixture
- expected success lines remain present for login, encrypt/decrypt, sign/verify, object destroy, and logout

Optional vendor regression coverage from `vendor-regression` guarantees that, when explicitly enabled and configured:

- solution restore/build/test still works with a non-SoftHSM PKCS#11 backend
- regression tests can run against pre-provisioned vendor token material
- required runtime env contract is validated before tests start

## Fixture behavior in CI

Both CI scripts create temporary fixture roots with `mktemp` and remove them on exit. CI does not depend on a pre-existing host token store or a checked-in SoftHSM configuration.

The fixture env contract comes from `eng/setup-softhsm-fixture.sh`, including:

- isolated `SOFTHSM2_CONF`
- resolved `PKCS11_MODULE_PATH`
- known token label and PINs
- default search/mechanism variables for smoke and regression runs
- `PKCS11_PROVISIONING_REGRESSION=1` for the opt-in `InitToken` test path

The `InitToken` provisioning regression is still conditional on `PKCS11_SO_PIN`; the fixture script writes it, so CI satisfies that requirement.

For the optional vendor lane, CI does not provision a fixture. The lane calls:

```bash
./eng/run-regression-tests.sh --use-existing-env
```

and expects the vendor token/module inputs to already be available via workflow config.
The script now applies the `baseline-rsa-aes` vendor compatibility profile by default; see `docs/vendor-regression.md`.

## Optional vendor lane setup

The vendor lane is opt-in and never runs on normal push/PR events.

Enablement path:

1. In GitHub repository settings, define Variables:
   - `VENDOR_PKCS11_MODULE_PATH`
   - `VENDOR_PKCS11_TOKEN_LABEL`
   - `VENDOR_PKCS11_FIND_LABEL`
   - `VENDOR_PKCS11_SIGN_FIND_LABEL`
2. Define Secret:
   - `VENDOR_PKCS11_USER_PIN`
3. Optional Secret (only needed for provisioning/admin test paths):
   - `VENDOR_PKCS11_SO_PIN`
4. Optional Variable if you want a distinct verify-key search label:
   - `VENDOR_PKCS11_VERIFY_FIND_LABEL`
5. Run **Actions -> ci -> Run workflow** with:
   - `run_vendor_lane=true`
   - optional `vendor_dependency_install_command` if your module needs extra installation/runtime setup

Guard behavior:

- if `run_vendor_lane` is `false`, vendor lane is not scheduled
- if `run_vendor_lane` is `true` but required config is missing, `vendor-regression` is skipped and `vendor-regression-config-missing` prints an informational message
- default contributors do not need vendor secrets to run or contribute through standard PR CI

## Local CI parity

Closest local equivalent:

```bash
sudo apt-get update
sudo apt-get install -y softhsm2 opensc file
dotnet restore Pkcs11Wrapper.sln
dotnet build Pkcs11Wrapper.sln -c Release --no-restore
./eng/run-regression-tests.sh
./eng/run-smoke-aot.sh
```

If you only need targeted troubleshooting:

- run `./eng/setup-softhsm-fixture.sh`
- `source` the printed env file
- run `dotnet test tests/Pkcs11Wrapper.Native.Tests/Pkcs11Wrapper.Native.Tests.csproj -c Release`
- run `dotnet run --project samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release`

That manual flow uses the same env contract while giving you direct access to the temporary fixture.

Local vendor-lane equivalent (pre-provisioned token/module, no SoftHSM fixture setup):

```bash
export PKCS11_USE_EXISTING_ENV=1
export PKCS11_VENDOR_PROFILE=baseline-rsa-aes
export PKCS11_MODULE_PATH='/path/to/vendor-pkcs11.so'
export PKCS11_TOKEN_LABEL='your-token-label'
export PKCS11_USER_PIN='your-pin'
export PKCS11_FIND_LABEL='existing-aes-label'
export PKCS11_SIGN_FIND_LABEL='existing-rsa-label'
./eng/run-regression-tests.sh --use-existing-env
```

See `docs/vendor-regression.md` for the defaulted search contract and the optional provisioning/admin path.
