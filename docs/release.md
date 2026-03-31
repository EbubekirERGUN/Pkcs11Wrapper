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

This executes restore, Release build, tests, NativeAOT smoke, and NuGet pack validation for both projects using the repository version from `Directory.Build.props`.

4. Review generated artifacts under `artifacts/packages/<version>/`.
5. Update release notes / changelog text in the platform where the release will be published.
6. Optional cross-platform sanity: confirm the Windows lane still builds, either via GitHub Actions or with a local `dotnet build samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release -r win-x64 --self-contained false` check.
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

- `Pkcs11Wrapper` and `Pkcs11Wrapper.Native` are both packable.
- The repository `README.md` is embedded into each package to keep NuGet package pages aligned with the repo baseline.
- Package publication is intentionally not automated from this repository yet; maintainers should publish only from a validated local tag/release candidate.
