# Release discipline

## Goals

- keep restore/build/test/smoke/pack reproducible
- make package contents predictable
- avoid ad-hoc version bumps and unpublished local state

## Release checklist

1. Confirm working tree is clean except the intended release changes.
2. Update the repository version in `Directory.Build.props` (`VersionPrefix`).
3. Run:

```bash
./eng/verify-release.sh
```

This executes restore, Release build, tests, Linux NativeAOT smoke, package creation, SourceLink/symbol validation, and local package-consumer restore/build checks for both packages using the repository version from `Directory.Build.props`.

4. Review generated artifacts under `artifacts/packages/<version>/` and `artifacts/packages/<version>-validation/`.
5. Update release notes / changelog text in the platform where the release will be published.
6. Optional cross-platform sanity: confirm the Windows lane still builds, either via GitHub Actions or with a local fixture-backed PowerShell run:

```powershell
.\eng\setup-softhsm-fixture.ps1 -DownloadPortable -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
.\eng\run-smoke.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1" -Strict
.\eng\run-smoke-aot.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1" -Strict
```

7. Tag and publish only after the maintainer confirms the package contents and validation output. Recommended tag format: `v<version>`.

If you want a starting point for the GitHub release text after the Windows support work, reuse or adapt `docs/release-notes/windows-compatibility.md`.

## Versioning guidance

- Use SemVer (`major.minor.patch`).
- Keep `Directory.Build.props` as the single source of truth for repository + package versioning.
- Patch: fixes, docs-only package metadata fixes, non-breaking compatibility expansions.
- Minor: additive managed API surface such as new PKCS#11 operations.
- Major: breaking API shape changes, behavior changes requiring consumer migration, or packaging identity changes.
- Recommended GitHub tag / release title format: `v<version>`.

See also: [docs/versioning.md](versioning.md)

## Packaging notes

- `Pkcs11Wrapper`, `Pkcs11Wrapper.Native`, `Pkcs11Wrapper.ThalesLuna.Native`, and `Pkcs11Wrapper.ThalesLuna` are packable.
- NuGet packages embed `docs/nuget/README.nuget.md`, which keeps the package page free of repo-relative links.
- Pack validation now checks for:
  - `README.nuget.md` inside each package
  - repository metadata in the nuspec
  - `snupkg` symbol packages for all four packages
  - embedded GitHub SourceLink data inside the portable PDBs
  - successful local restore/build from a file-based package source for all four packages
- Package publication is intentionally not automated from this repository yet; maintainers should publish only from a validated local tag/release candidate.
