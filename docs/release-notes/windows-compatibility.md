# Release note draft - Windows compatibility

## Summary

This release improves Windows support for `Pkcs11Wrapper` and adds a real Windows runtime regression path.

## Highlights

- Added platform-aware PKCS#11 module fallback helpers for SoftHSM on Linux, Windows, and macOS.
- Added a Windows GitHub Actions lane that installs OpenSC, provisions a real SoftHSM-for-Windows token, runs the regression suite, and executes the smoke sample.
- Added Windows-oriented engineering scripts:
  - `eng/setup-softhsm-fixture.ps1`
  - `eng/run-regression-tests.ps1`
  - `eng/run-smoke.ps1`
- Added Windows local setup documentation in `docs/windows-local-setup.md`.
- Updated compatibility and release docs to reflect the stronger Windows validation story.

## Notes

- Linux remains the deepest validation environment because it also carries the NativeAOT smoke path and the existing Bash fixture automation.
- Windows now has real runtime coverage through SoftHSM-for-Windows, not just build/API/layout checks.
