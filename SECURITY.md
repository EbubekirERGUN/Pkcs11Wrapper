# Security Policy

## Supported focus

Security-sensitive areas of this repository include:

- PKCS#11 wrapper behavior and correctness
- credential / PIN handling in admin flows
- audit integrity behavior
- key management workflows
- vendor compatibility assumptions that may affect security posture

## Reporting a vulnerability

If you believe you found a security issue, please avoid opening a public issue with exploit details.

Instead, report it privately to the project maintainer and include:

- affected area
- impact summary
- reproduction steps
- whether it affects Linux, Windows, or both
- whether it requires a specific vendor / token / module

## What not to commit

Please do **not** commit:

- real HSM credentials or user/SO PINs
- proprietary PKCS#11 vendor libraries
- exported secret/private key material
- production audit logs containing sensitive data

## Current security boundary

The current admin panel hardening is designed as a **strong local-host implementation**. It includes:

- cookie-based auth
- local roles (viewer / operator / admin)
- protected local PIN cache via ASP.NET Core Data Protection
- append-only chained audit entries with integrity verification

This is intentionally not a full external IAM / KMS integration yet.
