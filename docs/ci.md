# CI

## Workflow

`.github/workflows/ci.yml` defines:

- `build-test-aot` (default SoftHSM Linux lane)
- `admin-runtime-e2e` (Linux Playwright-backed admin runtime lane)
- `build-test-windows` (Windows SoftHSM regression lane with hosted-smoke limitation notes)
- `vendor-regression` (optional non-SoftHSM lane, manual dispatch only)

`.github/workflows/release.yml` defines:

- `preflight` (version/tag/release-notes alignment)
- `linux-release-validation` (`./eng/verify-release.sh` + release-bundle assembly)
- `windows-release-regression` (release-readiness regression on `windows-latest`)
- `publish-release` (optional NuGet push + GitHub release asset publication)

`.github/workflows/benchmarks.yml` defines:

- `linux-softhsm-benchmarks` (weekly/manual benchmark lane plus targeted push/PR validation for benchmark/reporting and performance-sensitive source changes)

Triggers:

- push to `main` and `master`
- all pull requests
- `workflow_dispatch` with optional vendor-lane inputs

Release workflow triggers:

- push tags matching `v*`
- `workflow_dispatch` with a required `version` input and optional GitHub release / NuGet publication flags

Benchmark workflow triggers:

- weekly schedule (`cron`)
- `workflow_dispatch`
- push to `main` / `master` when benchmark workflow/reporting inputs change
- pull requests that change benchmark workflow/reporting inputs
- targeted source changes in `benchmarks/**`, `src/Pkcs11Wrapper/**`, `src/Pkcs11Wrapper.Native/**`, `tests/Pkcs11Wrapper.Native.Tests/**`, `samples/Pkcs11Wrapper.Smoke/**`, benchmark scripts, and committed benchmark baselines

Workflow-level behavior:

- `permissions: contents: read`
- `concurrency` cancels superseded runs on the same ref
- each CI job has a 30-minute timeout
- `actions/setup-dotnet` caches NuGet packages based on `global.json`, `Directory.Build.props`, and project files

Release workflow behavior:

- `preflight` resolves the repository's **effective** version via MSBuild instead of assuming `VersionPrefix` alone
- tagged releases fail fast if `v<version>` and `docs/release-notes/v<version>.md` are not aligned
- Linux release validation reuses `./eng/verify-release.sh` instead of introducing a second packaging path
- release bundles include package artifacts, validation archives, Linux NativeAOT smoke output, `SHA256SUMS.txt`, and `release-manifest.json`
- NuGet publication is optional and only runs when the workflow is allowed to publish **and** `NUGET_API_KEY` is configured
- GitHub releases are created or updated from the checked-in release-notes markdown so release text stays reviewable in-repo

Ordered Linux steps:

- checkout the repository
- install the SDK pinned by `global.json`
- install native dependencies: `build-essential`, `softhsm2`, `opensc`, `file`
- create a CI artifact directory
- mark engineering scripts executable
- `dotnet restore Pkcs11Wrapper.sln`
- `dotnet build Pkcs11Wrapper.sln -c Release --no-restore`
- `./eng/run-regression-tests.sh` (this now also builds the Linux PKCS#11 v3 runtime shim before `dotnet test`)
- `./eng/run-smoke-aot.sh`
- upload captured CI logs plus the Linux NativeAOT publish output as Actions artifacts

Ordered admin runtime E2E steps:

- checkout the repository
- install the SDK pinned by `global.json`
- install baseline native dependencies (`build-essential`, `softhsm2`, `opensc`, `file`)
- create a dedicated admin-E2E artifact directory
- mark `eng/setup-softhsm-fixture.sh` and `eng/run-admin-e2e.sh` executable
- `dotnet restore Pkcs11Wrapper.sln`
- `dotnet build Pkcs11Wrapper.sln -c Release --no-restore`
- `./eng/run-admin-e2e.sh --no-restore --no-build`
- upload browser traces/screenshots plus runtime/server logs as Actions artifacts

Ordered Windows steps:

- checkout the repository
- install the SDK pinned by `global.json`
- install OpenSC via Chocolatey
- create a CI artifact directory before fixture setup so bootstrap logs are always captured
- provision a SoftHSM-for-Windows fixture with `eng/setup-softhsm-fixture.ps1 -DownloadPortable`
- `dotnet restore Pkcs11Wrapper.sln`
- `dotnet build Pkcs11Wrapper.sln -c Release --no-restore`
- `./eng/run-regression-tests.ps1`
- record the hosted-Windows smoke limitation in the job summary unless the runtime-smoke toggle is explicitly enabled
- upload fixture, regression, and any optional smoke artifacts

Job-level env:

- `DOTNET_NOLOGO=true`
- `DOTNET_CLI_TELEMETRY_OPTOUT=true`
- `CI=true`

## What CI guarantees

Regression coverage from `eng/run-regression-tests.sh` guarantees that:

- solution restore/build/test stays healthy on the pinned SDK
- the SoftHSM fixture contract is still valid
- the seeded AES and RSA objects are discoverable before tests start
- the xUnit suite still covers managed API shape, native layout assumptions, crypto flows, object lifecycle, admin operations, and PKCS#11 v3 runtime-present behavior through the Linux shim
- SoftHSM capability-absent coverage stays distinct from v3-runtime-present failures because both paths run in the same Linux regression lane

Admin runtime E2E coverage from `admin-runtime-e2e` guarantees that:

- the Blazor admin host still boots in CI against an isolated temporary storage root instead of repo-local mutable `App_Data`
- a deterministic bootstrap admin credential can be injected for automation without changing the default local first-run behavior
- critical authenticated admin flows still work end-to-end: login, device profile creation + connection test, slot inventory load, keys/object browse + detail open, Crypto API Access client/key/policy/alias management, PKCS#11 Lab execution, and telemetry viewing/filtering
- browser traces, screenshots, and runtime logs are captured as downloadable artifacts to make failures diagnosable instead of opaque

Native AOT coverage from `eng/run-smoke-aot.sh` guarantees that:

- `samples/Pkcs11Wrapper.Smoke` still publishes as NativeAOT for `linux-x64`
- the published entrypoint exists and is executable
- the smoke binary still completes key runtime paths against the fixture
- strict success-marker validation still holds for login, crypto, lifecycle, generation, wrap/unwrap, derive, and logout paths

Optional vendor regression coverage from `vendor-regression` guarantees that, when explicitly enabled and configured:

- solution restore/build/test still works with a non-SoftHSM PKCS#11 backend
- regression tests can run against pre-provisioned vendor token material
- required runtime env contract is validated before tests start
- missing vendor config is reported through a job summary instead of making the workflow file invalid

Windows runtime coverage from `build-test-windows` guarantees that:

- the solution still restores/builds on `windows-latest`
- a real SoftHSM-for-Windows fixture can be provisioned in CI
- the Windows lane still runs managed/admin regression coverage, while the crash-prone SoftHSM fixture native suites (`SoftHsmCryptRegressionTests` and `TelemetryRegressionTests`) are excluded from hosted Windows CI
- GitHub-hosted Windows CI currently skips those native fixture suites plus smoke and `win-x64` NativeAOT smoke because SoftHSM-for-Windows can crash during native `C_Initialize`; those remain local/manual Windows validation paths for now
- fixture/regression/smoke console logs are captured as downloadable Actions artifacts

Benchmark coverage from `benchmarks.yml` guarantees that, whenever the workflow runs:

- the benchmark project still restores and executes on the pinned SDK
- a real SoftHSM fixture can still be provisioned for performance measurement
- the latest benchmark run emits a GitHub-friendly job summary with date, environment, headline numbers, allocation figures, and optional committed-baseline deltas
- the latest benchmark summary plus raw BenchmarkDotNet exports/logs are published as an Actions artifact
- performance tracking stays repeatable instead of ad-hoc

## Fixture behavior in CI

Both Linux CI scripts create temporary fixture roots with `mktemp` and remove them on exit. CI does not depend on a pre-existing host token store or a checked-in SoftHSM configuration.

The fixture env contract comes from `eng/setup-softhsm-fixture.sh`, including:

- isolated `SOFTHSM2_CONF`
- resolved `PKCS11_MODULE_PATH`
- known token label and PINs
- default search/mechanism variables for smoke and regression runs
- `PKCS11_PROVISIONING_REGRESSION=1` for the opt-in `InitToken` test path

The `InitToken` provisioning regression is still conditional on `PKCS11_SO_PIN`; the fixture script writes it, so CI satisfies that requirement.

The admin runtime lane also creates a temporary admin storage root and injects:

- `AdminStorage__DataRoot` pointing at that temporary runtime folder
- `LocalAdminBootstrap__UserName` / `LocalAdminBootstrap__Password` for deterministic login
- `AdminRuntime__DisableHttpsRedirection=true` so Playwright can exercise the runtime over a bounded local HTTP endpoint in CI

That keeps the admin E2E run hermetic and avoids mutating `src/Pkcs11Wrapper.Admin.Web/App_Data`.

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
   - optional `VENDOR_PKCS11_PROFILE` (`baseline-rsa-aes` by default, set `luna-rsa-aes` for the documented Thales Luna manual profile)
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
5. If the chosen backend needs proprietary/native runtime setup (for example a Luna client install), pass it through:
   - `vendor_dependency_install_command` when manually dispatching the workflow
6. Run **Actions -> ci -> Run workflow** with:
   - `run_vendor_lane=true`
   - optional `vendor_dependency_install_command` if your module needs extra installation/runtime setup

Guard behavior:

- if `run_vendor_lane` is `false`, vendor lane is not scheduled
- if `run_vendor_lane` is `true` but required config is missing, `vendor-regression` exits early with a clear job summary and no restore/build/test work
- when provided, `VENDOR_PKCS11_PROFILE` is echoed into the job summary so you can tell whether you ran the generic baseline contract or the Luna-oriented profile
- default contributors do not need vendor secrets to run or contribute through standard PR CI

## Local CI parity

Closest local Linux equivalent:

```bash
sudo apt-get update
sudo apt-get install -y softhsm2 opensc file
dotnet restore Pkcs11Wrapper.sln
dotnet build Pkcs11Wrapper.sln -c Release --no-restore
./eng/run-regression-tests.sh
./eng/run-admin-e2e.sh
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

If the target is Thales Luna, set `PKCS11_VENDOR_PROFILE=luna-rsa-aes` and follow the documented env template at `eng/vendor-profiles/luna-rsa-aes.env.example`.

See `docs/vendor-regression.md` for the defaulted search contract and the optional provisioning/admin path.

Local benchmark equivalent:

```bash
./eng/run-benchmarks.sh
```

If you want to refresh the committed Linux baseline after reviewing the new numbers:

```bash
./eng/run-benchmarks.sh --update-docs
```

Windows local equivalent:

```powershell
.\eng\setup-softhsm-fixture.ps1 -DownloadPortable -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
.\eng\run-regression-tests.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
.\eng\run-smoke.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1" -Strict
.\eng\run-smoke-aot.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1" -Strict
.\eng\run-benchmarks.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
```

See `docs/windows-local-setup.md` for the full local Windows walkthrough.
