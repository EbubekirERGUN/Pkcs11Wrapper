# Pkcs11Wrapper

English | [Turkce](README.tr.md)

`Pkcs11Wrapper` is a .NET 10 PKCS#11 wrapper built around a small, explicit managed API over a native Cryptoki module. The project is Linux-first, validated with SoftHSM, compatible with NativeAOT, and structured for GitHub-friendly restore/build/test/smoke workflows.

This README stays at the repository workflow level. For implementation details and contributor-oriented notes, use the docs in `docs/`.

## Project scope

The current wrapper and validation surface covers:

- Module lifecycle: load, initialize, finalize, module info
- Slot, token, and mechanism enumeration
- Session open/close plus user and security-officer login flows
- Object search plus attribute read/write helpers
- Object creation, mutation, size queries, and destroy flows
- Single-part encrypt/decrypt operations
- Multipart encrypt/decrypt and operation-state resume paths
- Sign/verify operations
- Administrative operations: `CloseAllSessions`, `InitPin`, `SetPin`, `InitToken`
- Validation assets: SoftHSM fixture provisioning, regression scripts, NativeAOT smoke, GitHub Actions CI

`InitToken` regression coverage exists, but provisioning-style validation remains opt-in rather than part of every generic runtime scenario.

## Requirements

- .NET SDK `10.0.104` pinned by `global.json`
- Linux environment for the documented local and CI flows
- SoftHSM v2 library and tooling
- OpenSC `pkcs11-tool`
- `file` for the NativeAOT smoke script
- `bash` and `python3` for engineering scripts

Ubuntu/Debian package set used by CI:

```bash
sudo apt-get update
sudo apt-get install -y softhsm2 opensc file
```

## Quick start

1. Restore and build the solution:

```bash
dotnet restore Pkcs11Wrapper.sln
dotnet build Pkcs11Wrapper.sln -c Release --no-restore
```

2. Create a temporary SoftHSM fixture and load its generated environment file:

```bash
./eng/setup-softhsm-fixture.sh
source /tmp/path-from-script/pkcs11-fixture.env
```

The setup script prints the exact env file path. The fixture is temporary and intended for local validation or CI-style runs.

3. Run the regression workflow:

```bash
./eng/run-regression-tests.sh
```

4. Run the smoke sample directly:

```bash
dotnet run --project samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release
```

5. Run the NativeAOT smoke workflow:

```bash
./eng/run-smoke-aot.sh
```

## Core commands

```bash
dotnet restore Pkcs11Wrapper.sln
dotnet build Pkcs11Wrapper.sln -c Release --no-restore
dotnet test Pkcs11Wrapper.sln -c Release --nologo --logger "console;verbosity=minimal"
./eng/setup-softhsm-fixture.sh
./eng/run-regression-tests.sh
dotnet run --project samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release
./eng/run-smoke-aot.sh
```

## Documentation map

- `docs/development.md` - repository layout, local development loop, test layers, feature status
- `docs/softhsm-fixture.md` - SoftHSM fixture contract, seeded objects, env overrides, cleanup behavior
- `docs/ci.md` - GitHub Actions CI workflow and local parity guidance
- `docs/smoke.md` - smoke sample behavior, environment toggles, expected success output, troubleshooting

## Key paths

- `Pkcs11Wrapper.sln`
- `src/Pkcs11Wrapper/Pkcs11Wrapper.csproj`
- `src/Pkcs11Wrapper.Native/Pkcs11Wrapper.Native.csproj`
- `tests/Pkcs11Wrapper.Native.Tests/Pkcs11Wrapper.Native.Tests.csproj`
- `samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj`
- `eng/setup-softhsm-fixture.sh`
- `eng/run-regression-tests.sh`
- `eng/run-smoke-aot.sh`
- `.github/workflows/ci.yml`
