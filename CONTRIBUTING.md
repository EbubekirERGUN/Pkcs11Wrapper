# Contributing to Pkcs11Wrapper

Thanks for taking the time to contribute.

## What kinds of contributions are valuable?

- PKCS#11 wrapper correctness improvements
- regression coverage expansion
- vendor compatibility improvements
- Windows/Linux validation improvements
- admin panel UX / operations improvements
- documentation and release discipline improvements

## Development workflow

1. Fork or branch from `main`
2. Make a focused change
3. Add/update tests when behavior changes
4. Run validation locally
5. Open a pull request with a clear summary

## Validation expectations

For non-trivial changes, run as much of the relevant validation path as possible.

Typical commands:

```bash
dotnet test Pkcs11Wrapper.sln -c Release --nologo
./eng/run-regression-tests.sh
./eng/run-smoke-aot.sh
```

Windows local path:

```powershell
.\eng\setup-softhsm-fixture.ps1 -DownloadPortable -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
.\eng\run-regression-tests.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
.\eng\run-smoke.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
```

## Pull request guidelines

Please keep PRs focused and explain:

- what changed
- why it changed
- how it was validated
- any capability/vendor/runtime caveats

If your change affects public API shape, admin panel behavior, or PKCS#11 compatibility assumptions, call that out explicitly.

## Coding expectations

- prefer small, reviewable commits
- keep behavior explicit
- preserve raw PKCS#11 error fidelity where applicable
- do not silently weaken validation just to make CI green
- document token/vendor-specific limitations clearly

## Security and secrets

- never commit real credentials, PINs, vendor tokens, or proprietary PKCS#11 libraries
- use local fixture env files or CI secrets for sensitive values
- if you find a security issue, please follow [SECURITY.md](SECURITY.md)
