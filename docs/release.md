# Release discipline

## Goals

- keep restore/build/test/smoke/pack reproducible
- make package contents predictable
- avoid ad-hoc version bumps and unpublished local state

## Release checklist

1. Confirm working tree is clean except the intended release changes.
2. Run:

```bash
./eng/verify-release.sh <version>
```

This executes restore, Release build, tests, NativeAOT smoke, and NuGet pack validation for both projects.

3. Review generated artifacts under `artifacts/packages/<version>/`.
4. Update release notes / changelog text in the platform where the release will be published.
5. Optional cross-platform sanity: confirm the Windows lane still builds, either via GitHub Actions or with a local `dotnet build samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release -r win-x64 --self-contained false` check.
6. Tag and publish only after the maintainer confirms the package contents and validation output.

## Versioning guidance

- Use SemVer (`major.minor.patch`).
- Patch: fixes, docs-only package metadata fixes, non-breaking compatibility expansions.
- Minor: additive managed API surface such as new PKCS#11 operations.
- Major: breaking API shape changes, behavior changes requiring consumer migration, or packaging identity changes.

## Packaging notes

- `Pkcs11Wrapper` and `Pkcs11Wrapper.Native` are both packable.
- The repository `README.md` is embedded into each package to keep NuGet package pages aligned with the repo baseline.
- Package publication is intentionally not automated from this repository yet; maintainers should publish only from a validated local tag/release candidate.
