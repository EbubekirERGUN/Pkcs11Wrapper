# Pkcs11Wrapper

English | [Turkce](README.tr.md)

`Pkcs11Wrapper` is a .NET 10 PKCS#11 wrapper built around a small, explicit managed API over a native Cryptoki module. The project is Linux-first, validated with SoftHSM, compatible with NativeAOT, and structured for GitHub-friendly restore/build/test/smoke workflows.

This README stays at the repository workflow level. For implementation details and contributor-oriented notes, use the docs in `docs/`.

## Project scope

The current wrapper and validation surface covers:

- Module lifecycle: load, initialize, finalize, module info
- Optional initialize-time `CK_C_INITIALIZE_ARGS` flags and custom mutex callback wiring
- Slot, token, and mechanism enumeration
- Session open/close plus user and security-officer login flows
- Optional PKCS#11 v3 interface discovery via `C_GetInterface` / `C_GetInterfaceList`
- Object search plus attribute read/write helpers
- Object creation, mutation, size queries, and destroy flows
- Single-part encrypt/decrypt operations
- Multipart encrypt/decrypt and operation-state resume paths
- Sign/verify operations
- PKCS#11 v3 message-based encrypt/decrypt/sign/verify APIs when a module exposes a v3 interface
- Administrative operations: `CloseAllSessions`, `InitPin`, `SetPin`, `InitToken`
- PKCS#11 v3 session operations: `C_LoginUser`, `C_SessionCancel` when a module exposes a v3 interface
- Error reporting with taxonomy metadata (including retryability hints) while preserving raw `CK_RV`
- Validation assets: SoftHSM fixture provisioning, regression scripts, NativeAOT smoke, GitHub Actions CI, release verification script, NuGet pack metadata

GitHub Actions keeps SoftHSM as the default push/PR path and also provides an optional manual vendor PKCS#11 regression lane for maintainers. Setup details are in `docs/ci.md`, vendor-lane contract details are in `docs/vendor-regression.md`, and release verification is described in `docs/release.md`.

`InitToken` regression coverage exists, but provisioning-style validation remains opt-in rather than part of every generic runtime scenario.

## Current limitations (tracked)

- Current automated runtime validation does **not** yet include a module that positively exposes PKCS#11 v3 message APIs; those paths are currently covered by ABI/layout tests and capability-gated runtime behavior.
- Typed mechanism parameter helpers/marshalling cover ECDH, AES-GCM/CTR/CCM, and RSA-OAEP/PSS paths; less common mechanisms may still use raw byte payloads.
- The repository is Linux-first; other operating systems may work but are not part of the documented baseline yet.
- Package publication is still a maintainer-controlled action rather than an automated publish step.

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
- `docs/vendor-regression.md` - vendor compatibility profile, required env contract, capability-gated vs hard-fail rules
- `docs/smoke.md` - smoke sample behavior, environment toggles, expected success output, troubleshooting
- `docs/compatibility-matrix.md` - validated baseline, supported capability areas, known limitations
- `docs/release.md` - release checklist, versioning guidance, packaging notes

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
