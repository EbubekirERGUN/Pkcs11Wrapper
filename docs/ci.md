# CI

## Workflow

`.github/workflows/ci.yml` defines a single `build-test-aot` job on `ubuntu-latest`.

The job runs on pushes to `main` and `master`, plus all pull requests.

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

## Fixture behavior in CI

Both CI scripts create temporary fixture roots with `mktemp` and remove them on exit. CI does not depend on a pre-existing host token store or a checked-in SoftHSM configuration.

The fixture env contract comes from `eng/setup-softhsm-fixture.sh`, including:

- isolated `SOFTHSM2_CONF`
- resolved `PKCS11_MODULE_PATH`
- known token label and PINs
- default search/mechanism variables for smoke and regression runs
- `PKCS11_PROVISIONING_REGRESSION=1` for the opt-in `InitToken` test path

The `InitToken` provisioning regression is still conditional on `PKCS11_SO_PIN`; the fixture script writes it, so CI satisfies that requirement.

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
