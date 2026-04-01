# Release note draft - Windows compatibility

## Summary

This release improves Windows support for `Pkcs11Wrapper` and adds a real Windows runtime + `win-x64` NativeAOT validation path.

## Highlights

- Added platform-aware PKCS#11 module fallback helpers for SoftHSM on Linux, Windows, and macOS.
- Added a Windows GitHub Actions lane that installs OpenSC, provisions a real SoftHSM-for-Windows token, runs the regression suite, executes the runtime smoke sample, and validates a published `win-x64` NativeAOT smoke binary.
- Added Windows-oriented engineering scripts:
  - `eng/setup-softhsm-fixture.ps1`
  - `eng/run-regression-tests.ps1`
  - `eng/run-smoke.ps1`
  - `eng/run-smoke-aot.ps1`
- Added strict smoke-output validation shared across Linux and Windows smoke wrappers.
- Added Windows local setup documentation in `docs/windows-local-setup.md`.
- Updated compatibility and release docs to reflect the stronger Windows validation story.

## Notes

- Linux remains the primary benchmark/reference environment and still has the broadest local automation path.
- Windows now has real runtime and NativeAOT coverage through SoftHSM-for-Windows, not just build/API/layout checks.
