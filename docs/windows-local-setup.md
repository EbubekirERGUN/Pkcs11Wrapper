# Windows local setup

## Goal

This guide brings up a local Windows development/test environment that can run the real PKCS#11 regression suite and smoke sample against SoftHSM-for-Windows.

## Prerequisites

Install these first:

1. **.NET 10 SDK**
2. **OpenSC** (for `pkcs11-tool.exe`)
   - easiest path on developer machines:

```powershell
choco install opensc -y
```

3. Optional but recommended if you use the portable SoftHSM package:
   - Microsoft Visual C++ Redistributable (if your machine does not already have the required runtime)

## Fast path

From the repository root in PowerShell:

```powershell
.\eng\setup-softhsm-fixture.ps1 -DownloadPortable -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
. "$env:TEMP\pkcs11-fixture.ps1"
```

What this does:

- downloads the official portable SoftHSM-for-Windows package (currently `v2.5.0`) if needed
- creates a temporary token store and `softhsm2.conf`
- initializes a token
- provisions one AES key and one RSA keypair
- writes a PowerShell env file with the `PKCS11_*` variables expected by the regression suite and smoke sample

## Run the regression suite

```powershell
.\eng\run-regression-tests.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
```

Or, if you want the script to set up the fixture automatically:

```powershell
.\eng\run-regression-tests.ps1 -DownloadPortable
```

## Run the smoke sample

```powershell
.\eng\run-smoke.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
```

## Manual module path notes

The helper defaults to these Windows SoftHSM module candidates:

- `softhsm2-x64.dll`
- `softhsm2.dll`

If your installation differs, set `PKCS11_MODULE_PATH` explicitly before running the sample or tests.

## Common troubleshooting

### `pkcs11-tool.exe` not found
Install OpenSC or set `PKCS11_TOOL_PATH` explicitly.

### SoftHSM package not found
Pass `-DownloadPortable` to the setup script or set `PKCS11_SOFTHSM_ROOT` to an existing SoftHSM-for-Windows installation root.

### DLL load failure
This usually means the portable package dependencies are missing or the wrong architecture was chosen. Try the 64-bit package and confirm the Visual C++ runtime is installed.

### Want to keep the fixture around?
Pass a stable path:

```powershell
.\eng\setup-softhsm-fixture.ps1 -FixtureRoot "$PWD\.tmp\windows-fixture" -EnvFilePath "$PWD\.tmp\windows-fixture\pkcs11-fixture.ps1" -DownloadPortable
```
