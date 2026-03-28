# Smoke sample

## Purpose

`samples/Pkcs11Wrapper.Smoke/Program.cs` is the end-to-end sample and smoke executable for the wrapper. It loads a PKCS#11 module, prints module and slot information, chooses a token-present slot, and then conditionally exercises login, object search, encrypt/decrypt, multipart, operation-state, sign/verify, and object lifecycle flows.

It is also the executable used by `eng/run-smoke-aot.sh` after native AOT publish.

## Running it

With a fixture-backed environment:

```bash
./eng/setup-softhsm-fixture.sh
source /tmp/path-from-script/pkcs11-fixture.env
dotnet run --project samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release
```

You can also pass the module path as the first argument. If no argument or env value is set, Linux falls back to `libsofthsm2.so`.

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

## Typical success lines

`eng/run-smoke-aot.sh` currently treats these lines as required success markers:

- `Login succeeded.`
- `Encrypt/decrypt smoke:`
- `roundTrip=True`
- `Sign/verify smoke:`
- `verified=True, invalidVerified=False`
- `Object lifecycle destroy: foundAfterDestroy=False`
- `Logout succeeded.`

You will also usually see module info, slot count, mechanism listings, selected slot reason, and object search summaries.

## Common failure causes

- module path cannot be loaded or resolves to the wrong architecture
- token selection variables point at a token that is not present
- `PKCS11_USER_PIN` is missing, which skips the authenticated portion of the smoke
- search filters do not match a usable key, so encrypt/decrypt or sign/verify gets skipped
- multipart IV or plaintext values are malformed; AES-CBC multipart expects a 16-byte IV and block-aligned plaintext
- the module does not support operation-state export/import, which causes that portion to be skipped rather than treated as a hard failure
- object lifecycle requires a read-write session and permissions to create token objects

## Relationship to AOT smoke

`eng/run-smoke-aot.sh` publishes this project to `artifacts/smoke-aot/linux-x64`, runs the produced `Pkcs11Wrapper.Smoke` binary, captures output to a temp log, and checks for the success lines listed above. Any missing required line fails the script.
