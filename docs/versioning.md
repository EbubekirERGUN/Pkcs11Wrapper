# Versioning

`Pkcs11Wrapper` uses SemVer (`major.minor.patch`).

## Source of truth

The repository version is defined centrally in `Directory.Build.props` via the effective `Version` that flows from `VersionPrefix` and optional `VersionSuffix`.

Current version:

- `0.1.0`

This value flows into:

- assembly version (`0.1.0.0`)
- file version (`0.1.0.0`)
- informational version (`0.1.0`)
- NuGet package version (`0.1.0`)
- release-notes file naming (`docs/release-notes/v0.1.0.md`)
- Git tags and GitHub releases (recommended format: `v0.1.0`)

## Release tag format

Use:

- `v0.1.0`
- `v0.1.1`
- `v0.2.0`

## When to bump which number?

- Patch: bug fixes, docs-only package metadata fixes, non-breaking compatibility expansions
- Minor: additive API surface or meaningful new capabilities
- Major: breaking API/behavior changes or packaging identity changes

## Pre-release convention

When needed, set `VersionSuffix` to values such as:

- `preview.1`
- `rc.1`

That yields versions like:

- `0.2.0-preview.1`
- `1.0.0-rc.1`

The same effective version also drives:

- release tags such as `v0.2.0-preview.1`
- release-note files such as `docs/release-notes/v0.2.0-preview.1.md`
- release preflight checks in `eng/release-preflight.sh`
