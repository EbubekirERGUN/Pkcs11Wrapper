# GitHub showcase suggestions

Use this file as the source of truth for repository presentation settings that cannot be stored directly in git.

The current committed README showcase assets live under [`docs/showcase/2026-04-final/`](showcase/2026-04-final/README.md). This final set intentionally supersedes the earlier preview-only PR #63 concept instead of keeping a second preview gallery around.

## Suggested repository description

Modern .NET 10 PKCS#11 wrapper with Linux and Windows support, PKCS#11 v3 interface/message awareness, and a Blazor Server admin panel for HSM operations.

## Suggested topics

- pkcs11
- hsm
- cryptography
- dotnet
- csharp
- blazor
- aspnet-core
- nativeaot
- smartcard
- security

## Suggested website

If you want a repo website field, use one of these:

- project documentation root
- release page
- future demo page for the admin panel

## Suggested social preview image

Recommended composition:

- project title: `Pkcs11Wrapper`
- subtitle: `.NET 10 PKCS#11 Wrapper + Blazor Admin Panel`
- small badges or callouts:
  - Linux + Windows
  - PKCS#11 v3 aware
  - HSM / Slots / Devices / Sessions
- base visual: crop from `docs/showcase/2026-04-final/admin-dashboard.png`

## Suggested pinned release headline

`Pkcs11Wrapper: modern .NET 10 PKCS#11 wrapper with Windows/Linux support and Blazor admin panel`

## Current committed README showcase assets

The README now uses this smaller final set:

1. `docs/showcase/2026-04-final/admin-dashboard.png`
2. `docs/showcase/2026-04-final/admin-devices.png`
3. `docs/showcase/2026-04-final/admin-slots.png` (captured from the loaded slot inventory state, not the pre-load shell)

Telemetry, security/admin recovery, and Crypto API Access are intentionally carried by README copy and linked docs rather than expanding the showcase into a second screenshot row.

If the repo needs one more follow-up asset later, add a **single short admin panel clip** instead of expanding back into a large screenshot dump.
