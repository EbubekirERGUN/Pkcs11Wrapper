# Development

## Repository layout

- `src/Pkcs11Wrapper` - managed API surface used by consumers
- `src/Pkcs11Wrapper.Native` - low-level PKCS#11 function table and native interop layer
- `src/Pkcs11Wrapper.CryptoApi` - stateless ASP.NET Core machine-facing host scaffold for future crypto request/response flows
- `src/Pkcs11Wrapper.ThalesLuna.Native` - conservative Thales Luna `CA_GetFunctionList` bootstrap/interp layer for Luna-only extensions
- `src/Pkcs11Wrapper.ThalesLuna` - managed Luna extension entry point and capability/family facades
- `tests/Pkcs11Wrapper.CryptoApi.Tests` - xUnit coverage for crypto-host config normalization and readiness/runtime descriptor behavior
- `tests/Pkcs11Wrapper.Native.Tests` - xUnit regression suite covering layout, API shape, and SoftHSM-backed behavior
- `tests/Pkcs11Wrapper.ThalesLuna.Tests` - xUnit suite covering the Luna extension skeleton API, minimal interop layout, and shim-backed bootstrap behavior
- `samples/Pkcs11Wrapper.Smoke` - executable smoke sample used by runtime and NativeAOT validation paths
- `eng` - engineering scripts for fixture setup, regression execution, smoke validation, benchmarks, release verification, and package inspection
- `artifacts` - generated outputs such as `artifacts/smoke-aot/linux-x64`
- `global.json` and `Directory.Build.props` - SDK pinning and shared build settings (`net10.0`, nullable, warnings-as-errors, AOT analyzers)

## Development loop

Typical local loop:

```bash
dotnet restore Pkcs11Wrapper.sln
dotnet build Pkcs11Wrapper.sln -c Release --no-restore
./eng/run-regression-tests.sh
./eng/run-smoke-aot.sh
./eng/run-benchmarks.sh
```

Notes:

- `eng/run-regression-tests.sh` provisions its own temporary SoftHSM fixture, builds a tiny PKCS#11 v3 runtime shim plus a Luna `CA_GetFunctionList` bootstrap shim on Linux, validates the expected AES and RSA objects, then runs `dotnet test` on `Pkcs11Wrapper.sln`.
- `eng/run-regression-tests.sh --use-existing-env` skips fixture provisioning and uses existing `PKCS11_*` environment variables. This is intended for optional vendor-module validation and now supports the default `baseline-rsa-aes` profile plus the documented `luna-rsa-aes` Thales Luna profile in `docs/vendor-regression.md`.
- `eng/run-smoke-aot.sh` provisions its own temporary fixture, publishes `samples/Pkcs11Wrapper.Smoke` with `/p:PublishAot=true`, then executes the produced binary with strict output validation.
- `eng/run-benchmarks.sh` provisions its own temporary fixture, runs the `BenchmarkDotNet` suite, and writes the latest benchmark summary under `artifacts/benchmarks/latest/summary.md` plus machine-readable JSON.
- `eng/run-benchmarks.sh --update-docs` additionally refreshes the committed Linux baseline files at `docs/benchmarks/latest-linux-softhsm.md` and `docs/benchmarks/latest-linux-softhsm.json` after a trustworthy rerun.
- If you want to inspect behavior interactively, create a fixture with `eng/setup-softhsm-fixture.sh`, `source` the generated env file, and run the smoke sample or targeted `dotnet test` commands manually.
- Windows local development is supported for restore/build/test flows. The repository also includes PowerShell helpers (`eng/setup-softhsm-fixture.ps1`, `eng/run-regression-tests.ps1`, `eng/run-smoke.ps1`, `eng/run-smoke-aot.ps1`) so Windows runtime and NativeAOT checks can run against SoftHSM-for-Windows without relying on the Bash-only fixture path.
- Windows also has a matching benchmark entry point through `eng/run-benchmarks.ps1`.
- `eng/verify-release.sh` now validates package contents, SourceLink-enabled symbols, and local package consumption in addition to build/test/smoke work.

## Test layers

`tests/Pkcs11Wrapper.Native.Tests` currently gives three main layers of coverage:

- API and shape checks - `ManagedApiSurfaceTests.cs` verifies that the intended managed surface exists.
- Interop layout checks - `NativeTypeLayoutTests.cs` validates native type and function-list expectations.
- SoftHSM-backed regressions - `SoftHsmCryptRegressionTests.cs` validates realistic runtime flows against a PKCS#11 module.
- PKCS#11 v3 shim regressions - `Pkcs11V3ShimRuntimeTests.cs` validates interface discovery plus real v3 login/session-cancel/message-encrypt flows against a deterministic Linux-only shim.

`tests/Pkcs11Wrapper.ThalesLuna.Tests` adds the first Luna-specific validation layer:

- API and namespace checks for the managed/native Luna skeleton packages
- minimal native layout validation for the conservative Luna function-list header
- Linux shim-backed bootstrap checks for missing export, successful `CA_GetFunctionList`, `CKR_FUNCTION_NOT_SUPPORTED`, and null-pointer contract failures

The SoftHSM regression layer currently exercises:

- search and attribute reads
- single-part encrypt/decrypt length probes and round-trip behavior
- multipart update/final behavior
- operation-state capture and resume
- sign/verify including invalid-signature failure behavior
- data object create/update/destroy lifecycle
- administrative flows for `SetPin`, `InitPin`, `CloseAllSessions`, and opt-in `InitToken`

## Feature status

The wrapper surface implemented through the current phase set includes:

- init/finalize and module metadata
- slot/token/mechanism enumeration
- session open/close plus login/logout
- object search and object attribute accessors
- object creation, mutation, size queries, and destroy
- encrypt/decrypt and sign/verify APIs
- multipart operations and operation-state APIs
- optional PKCS#11 v3 interface discovery and message-based API surface
- optional `C_LoginUser` / `C_SessionCancel` through the discovered v3 interface
- opt-in structured operation telemetry with duration, result/exception, slot/session/mechanism context, redacted field summaries for sensitive PKCS#11 inputs, and admin-side retention/export/correlation controls in the admin panel
- a separate stateless Crypto API host scaffold with DI/config, service documents, and health/readiness endpoints
- administrative operations for session invalidation and token/PIN provisioning
- NativeAOT smoke validation through the sample app on Linux and Windows

Notable current assumptions:

- documented full fixture/smoke validation flow exists on Linux, and parallel Windows runtime + NativeAOT validation paths exist through the PowerShell SoftHSM-for-Windows helpers
- SoftHSM is the reference module used by scripts, tests, and CI
- GitHub Actions runs a Windows SoftHSM runtime regression lane plus a Windows `win-x64` NativeAOT smoke lane to keep cross-platform support from regressing
- a separate optional CI lane can run regression tests against a configured non-SoftHSM vendor module
- vendor validation distinguishes capability-gated skips from broken env/object-contract failures
- provisioning regression for `InitToken` is intentionally opt-in and only runs when `PKCS11_PROVISIONING_REGRESSION=1` and `PKCS11_SO_PIN` are available
- current SoftHSM builds used in CI do not export `C_GetInterface*`, so Linux regression now pairs SoftHSM capability-absent coverage with a deterministic v3 shim for runtime-present validation

## Runtime contracts

### Thread-safety and lifecycle (`Pkcs11Module` / `Pkcs11Session`)

- `Pkcs11Module` can be shared across threads for concurrent metadata/enumeration calls and concurrent session-open calls.
- `Pkcs11Session` is intended as a single-owner handle for stateful operation sequences; do not issue overlapping calls against the same session from multiple threads.
- A session handle is invalid after `Close`, `Dispose`, `CloseAllSessions`, module `Finalize`, or module `Dispose`; follow-up calls are expected to fail with PKCS#11 session/state return values.

### CKR taxonomy contract

- Wrapper errors expose taxonomy metadata that classifies CKR outcomes into stable high-level categories (`Success`, `Lifecycle`, `StateConflict`, `InputValidation`, `Authentication`, `ObjectHandle`, `Capability`, `Resource`, `Device`, `Session`, `Integrity`, `Unknown`).
- Taxonomy metadata includes a retryability hint via `IsRetryable` (`true`/`false`) for control-flow policy.
- The raw `CK_RV` value is always preserved and remains the authoritative signal for exact module/token semantics.

### Telemetry contract

- Telemetry is disabled unless a consumer provides `IPkcs11OperationTelemetryListener`.
- Emitted events carry operation/native-operation names, duration, status, raw return value when available, plus optional slot/session/mechanism metadata and redacted `Fields`.
- The redaction contract distinguishes `SafeMetadata`, `LengthOnly`, `Masked`, `Hashed`, and `NeverLog` buckets so future tooling can render telemetry without leaking PKCS#11 secrets.
- Listener exceptions are swallowed so telemetry remains observational and cannot break the primary PKCS#11 operation flow.

## Related docs

- Fixture contract: `docs/softhsm-fixture.md`
- CI behavior: `docs/ci.md`
- Telemetry redaction policy: `docs/telemetry-redaction.md`
- Admin telemetry operations: `docs/admin-telemetry-operations.md`
- Crypto API deployment model: `docs/crypto-api-deployment.md`
- Crypto API host scaffold: `docs/crypto-api-host.md`
- Smoke sample usage: `docs/smoke.md`
- Compatibility matrix: `docs/compatibility-matrix.md`
- Thales Luna integration guide: `docs/luna-integration.md`
- Thales Luna audit: `docs/luna-compatibility-audit.md`
- Thales Luna vendor-extension design: `docs/luna-vendor-extension-design.md`
- Vendor-native audit evaluation: `docs/vendor-audit-integration.md`
- Release discipline: `docs/release.md`
- Performance baselines: `docs/benchmarks.md`
