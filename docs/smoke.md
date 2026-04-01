# Smoke sample

## Purpose

`samples/Pkcs11Wrapper.Smoke/Program.cs` is the end-to-end sample and smoke executable for the wrapper. It loads a PKCS#11 module, prints module and slot information, chooses a token-present slot, and then conditionally exercises login, object search, encrypt/decrypt, multipart, operation-state, sign/verify, and object lifecycle flows.

It is also the executable used by:

- `eng/run-smoke-aot.sh` for the Linux NativeAOT lane
- `eng/run-smoke.ps1` for the Windows runtime lane
- `eng/run-smoke-aot.ps1` for the Windows `win-x64` NativeAOT lane

## Running it

With a fixture-backed environment:

```bash
./eng/setup-softhsm-fixture.sh
source /tmp/path-from-script/pkcs11-fixture.env
dotnet run --project samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release
```

On Windows PowerShell:

```powershell
.\eng\setup-softhsm-fixture.ps1 -DownloadPortable -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1"
. "$env:TEMP\pkcs11-fixture.ps1"
.\eng\run-smoke.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1" -Strict
.\eng\run-smoke-aot.ps1 -UseExistingEnv -EnvFilePath "$env:TEMP\pkcs11-fixture.ps1" -Strict
```

You can also pass the module path as the first argument. If no argument or env value is set, the sample falls back to a platform-specific SoftHSM module name when one is known:

- Linux: `libsofthsm2.so`
- Windows: `softhsm2-x64.dll`, then `softhsm2.dll`
- macOS: `libsofthsm2.dylib`, then `softhsm2.dylib`

If the current platform has no built-in fallback, provide `PKCS11_MODULE_PATH` explicitly.

## Token selection

Slot selection logic prefers, in order:

- explicit `PKCS11_TOKEN_LABEL`, `PKCS11_TOKEN_SERIAL`, or `PKCS11_SLOT_ID` match
- first initialized token-present slot
- first slot with an initialized user PIN
- first token-present slot fallback

If an explicit filter does not match, the sample logs that it is falling back to token flags.

## Important environment variables

Core connection and login:

- `PKCS11_MODULE_PATH`
- `PKCS11_TOKEN_LABEL`
- `PKCS11_TOKEN_SERIAL`
- `PKCS11_SLOT_ID`
- `PKCS11_USER_PIN`

Default object search and single-part encrypt/decrypt:

- `PKCS11_FIND_LABEL`
- `PKCS11_FIND_ID_HEX`
- `PKCS11_FIND_CLASS`
- `PKCS11_FIND_KEY_TYPE`
- `PKCS11_REQUIRE_ENCRYPT`
- `PKCS11_REQUIRE_DECRYPT`
- `PKCS11_KEY_HANDLE`
- `PKCS11_MECHANISM`
- `PKCS11_MECHANISM_PARAM_HEX`
- `PKCS11_SMOKE_PLAINTEXT`

Multipart and operation-state:

- `PKCS11_MULTIPART`
- `PKCS11_OPERATION_STATE`
- `PKCS11_MULTIPART_IV_HEX`
- `PKCS11_MULTIPART_PLAINTEXT_HEX`

Sign/verify:

- `PKCS11_SIGN_MECHANISM`
- `PKCS11_SIGN_MECHANISM_PARAM_HEX`
- `PKCS11_SIGN_FIND_LABEL`, `PKCS11_SIGN_FIND_ID_HEX`, `PKCS11_SIGN_FIND_CLASS`, `PKCS11_SIGN_FIND_KEY_TYPE`, `PKCS11_SIGN_REQUIRE_SIGN`
- `PKCS11_VERIFY_FIND_LABEL`, `PKCS11_VERIFY_FIND_ID_HEX`, `PKCS11_VERIFY_FIND_CLASS`, `PKCS11_VERIFY_FIND_KEY_TYPE`, `PKCS11_VERIFY_REQUIRE_VERIFY`
- `PKCS11_SIGN_KEY_HANDLE`, `PKCS11_VERIFY_KEY_HANDLE`
- `PKCS11_SIGN_DATA`

Object lifecycle:

- `PKCS11_OBJECT_LIFECYCLE`
- `PKCS11_OBJECT_LABEL`
- `PKCS11_OBJECT_APPLICATION`
- `PKCS11_OBJECT_VALUE_HEX`

## Strict validation markers

`eng/validate-smoke-output.py` is the shared strict validator used by the Linux and Windows smoke wrappers.

Required success markers now include:

- `Login succeeded.`
- `Encrypt/decrypt smoke:` with `roundTrip=True`
- `Multipart smoke:` with `roundTrip=True`
- `Digest smoke:` with `matchesMultipart=True`
- `Random smoke:` with `allZero=False` and `distinct=True`
- `Sign/verify smoke:` with `verified=True, invalidVerified=False`
- `Multipart sign/verify smoke:` with `matchesSinglePart=True, verified=True, invalidVerified=False, shortVerified=False`
- `Object lifecycle destroy:` with `foundAfterDestroy=False`
- `Generate key smoke:` with `roundTrip=True`
- `Generate key pair smoke:` with `publicMatch=True, privateMatch=True, verified=True`
- `Wrap/unwrap smoke:` with `roundTrip=True`
- `Derive key smoke:` with `roundTrip=True`
- `Logout succeeded.`

Operation-state remains capability-gated: strict validation accepts either a successful `Operation-state smoke:` line with `matchesBaseline=True` or the explicit SoftHSM-style skip marker that says the module reports operation state as unavailable.

## Common failure causes

- module path cannot be loaded or resolves to the wrong architecture
- on Windows, the installed module name may differ from the default SoftHSM-for-Windows fallback; set `PKCS11_MODULE_PATH` explicitly if needed
- token selection variables point at a token that is not present
- `PKCS11_USER_PIN` is missing, which skips the authenticated portion of the smoke
- search filters do not match a usable key, so encrypt/decrypt or sign/verify gets skipped
- multipart IV or plaintext values are malformed; AES-CBC multipart expects a 16-byte IV and block-aligned plaintext
- the module does not support operation-state export/import, which causes that portion to emit an explicit capability-gated skip marker
- object lifecycle requires a read-write session and permissions to create token objects

## Relationship to runtime and NativeAOT smoke

- `eng/run-smoke.ps1` captures the Windows runtime log under `artifacts/smoke-runtime/windows/smoke.log` and can enforce strict validation.
- `eng/run-smoke-aot.sh` publishes this project to `artifacts/smoke-aot/linux-x64`, runs the produced `Pkcs11Wrapper.Smoke` binary, captures output to `artifacts/smoke-aot/linux-x64/smoke.log`, and validates the required markers.
- `eng/run-smoke-aot.ps1` does the same for `artifacts/smoke-aot/win-x64` after publishing a `win-x64` NativeAOT binary.

Any missing required line fails the wrapper script and therefore fails CI or release validation.
