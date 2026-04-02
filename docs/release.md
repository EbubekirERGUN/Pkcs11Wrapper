# Release discipline

## Goals

- keep restore/build/test/smoke/pack reproducible
- make package contents predictable
- avoid ad-hoc version bumps and unpublished local state

## Release checklist

1. Confirm working tree is clean except the intended release changes.
2. Update the repository version in `Directory.Build.props` (`VersionPrefix`, and `VersionSuffix` when needed for pre-release builds).
3. Add or update the release notes file for the exact tag/version you intend to publish:

```text
docs/release-notes/v<version>.md
```

Examples:

- `docs/release-notes/v0.1.0.md`
- `docs/release-notes/v0.2.0-rc.1.md`

4. Run:

```bash
./eng/verify-release.sh
```

This now performs release preflight first and fails fast when:

- the requested version does not match the repository's **effective** package version
- the Git tag format would not be `v<version>`
- the matching `docs/release-notes/v<version>.md` file is missing

After preflight, it executes restore, Release build, tests, Linux NativeAOT smoke, package creation, SourceLink/symbol validation, and local package-consumer restore/build checks for all four packages using the repository's effective version.

5. Review generated artifacts under `artifacts/packages/<version>/` and `artifacts/packages/<version>-validation/`.
6. Optional local packaging bundle check:

```bash
./eng/assemble-release-artifacts.sh <version>
```

That creates a GitHub-release-ready bundle under `artifacts/releases/v<version>/` with:

- validated `.nupkg` and `.snupkg` files
- a bundled Linux NativeAOT smoke artifact archive
- bundled release-validation logs/output
- `SHA256SUMS.txt`
- `release-manifest.json`

7. Optional cross-platform sanity: confirm the Windows lane still builds, either via GitHub Actions or with a local fixture-backed PowerShell run:

```powershell
.\eng\setup-softhsm-fixture.ps1 -DownloadPortable -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
.\eng\run-smoke.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1" -Strict
.\eng\run-smoke-aot.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1" -Strict
```

8. Push the release tag after the maintainer confirms the package contents and validation output. Recommended tag format: `v<version>`.

```bash
git tag v<version>
git push origin v<version>
```

The tagged release workflow now automates:

- release preflight (`version` / `tag` / release-notes alignment)
- `./eng/verify-release.sh`
- Windows release-readiness regression on `windows-latest`
- release-bundle assembly with checksums and manifest
- GitHub release creation/update with the checked-in release notes body
- optional NuGet publication when `NUGET_API_KEY` is configured

You can also run the same workflow manually via **Actions -> release -> Run workflow** to dry-run a release candidate from a branch/ref before pushing the tag.

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
  - nuspec/package version alignment with the requested release version
  - `snupkg` symbol packages for all four packages
  - embedded GitHub SourceLink data inside the portable PDBs
  - successful local restore/build from a file-based package source for all four packages
- Tagged GitHub releases now automate package artifact publication to the GitHub release itself. NuGet publication is also automated when `NUGET_API_KEY` is configured; otherwise the workflow skips NuGet push and records that explicitly in the run summary.
