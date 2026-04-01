# SoftHSM fixture

## Purpose

`eng/setup-softhsm-fixture.sh` creates a temporary SoftHSM-backed PKCS#11 environment for local validation and CI. It provisions a fresh token, seeds a known AES key and RSA keypair, writes an env file, and points all consumers at an isolated `SOFTHSM2_CONF`.

This fixture is intentionally ephemeral. By default it lives under a new `mktemp` directory and is safe to discard after the shell session or calling script exits.

## Required tools

- `softhsm2-util`
- `pkcs11-tool`
- `python3`
- a resolvable SoftHSM PKCS#11 module, usually `libsofthsm2.so`

Module resolution order inside the script:

- `PKCS11_MODULE_PATH` if already set
- `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`
- `/usr/lib64/softhsm/libsofthsm2.so`
- `/usr/lib/softhsm/libsofthsm2.so`
- `libsofthsm2.so` if visible via `ldconfig`

If none resolve, the script exits and asks for `PKCS11_MODULE_PATH`.

## What the script does

`eng/setup-softhsm-fixture.sh`:

- creates a fixture root directory and token store
- writes a dedicated `softhsm2.conf`
- exports `SOFTHSM2_CONF` for the current script process
- initializes a token with a known label, SO PIN, and user PIN
- creates one AES-256 secret key and one RSA-2048 keypair via `pkcs11-tool`
- writes a shell env file with all variables consumed by tests and smoke runs
- prints the object listing and the env file location

If you pass a path argument, the script writes the env file there and uses its parent directory as the fixture root:

```bash
./eng/setup-softhsm-fixture.sh /tmp/pkcs11-fixture/pkcs11-fixture.env
source /tmp/pkcs11-fixture/pkcs11-fixture.env
```

## Seeded token and objects

Default seeded objects:

- token label: `Pkcs11Wrapper CI Token`
- user PIN: `123456`
- SO PIN: `12345678`
- AES key: label `ci-aes`, id `A1`, class `secret`, key type `aes`
- RSA keypair: label `ci-rsa`, id `B2`, private class `private`, public class `public`, key type `rsa`

The generated env file also enables smoke/test defaults for:

- AES-CBC encryption/decryption using mechanism `0x1085`
- multipart encrypt/decrypt and operation-state paths
- RSA PKCS#1 sign/verify using mechanism `0x40`
- object lifecycle smoke data
- opt-in provisioning regression flag `PKCS11_PROVISIONING_REGRESSION=1`

## Environment contract

Variables written by the script are the fixture contract used by `eng/run-regression-tests.sh`, `eng/run-smoke-aot.sh`, `eng/run-smoke.ps1`, `eng/run-smoke-aot.ps1`, `samples/Pkcs11Wrapper.Smoke/Program.cs`, and `tests/Pkcs11Wrapper.Native.Tests/SoftHsmCryptRegressionTests.cs`.

Key variables:

- `PKCS11_FIXTURE_ROOT` - temp root for the whole fixture
- `PKCS11_FIXTURE_ENV_FILE` - generated env file path
- `SOFTHSM2_CONF` - isolated SoftHSM config file
- `PKCS11_MODULE_PATH` - PKCS#11 library path used by the wrapper
- `PKCS11_TOKEN_LABEL`, `PKCS11_USER_PIN`, `PKCS11_SO_PIN`
- `PKCS11_FIND_*` - default AES search filters
- `PKCS11_MECHANISM`, `PKCS11_MECHANISM_PARAM_HEX`, `PKCS11_SMOKE_PLAINTEXT`
- `PKCS11_MULTIPART*`, `PKCS11_OPERATION_STATE`
- `PKCS11_SIGN_*`, `PKCS11_VERIFY_*`
- `PKCS11_OBJECT_*`
- `PKCS11_PROVISIONING_REGRESSION`

## Override variables

The script supports override inputs before execution:

- `PKCS11_MODULE_PATH`
- `PKCS11_TOKEN_LABEL_OVERRIDE`
- `PKCS11_USER_PIN_OVERRIDE`
- `PKCS11_SO_PIN_OVERRIDE`
- `PKCS11_AES_LABEL_OVERRIDE`
- `PKCS11_AES_ID_HEX_OVERRIDE`
- `PKCS11_RSA_LABEL_OVERRIDE`
- `PKCS11_RSA_ID_HEX_OVERRIDE`

These only affect fixture creation. Consumers should load the generated env file afterward so every later step sees the resolved values.

## Local reruns and cleanup

- Running the script again without arguments creates a new temp fixture and does not reuse a prior token store.
- Passing an explicit env file path makes reruns predictable because the fixture root becomes that file's parent directory.
- `eng/run-regression-tests.sh`, `eng/run-smoke-aot.sh`, `eng/run-smoke.ps1`, and `eng/run-smoke-aot.ps1` always create or consume fixture roots explicitly and remove temporary ones when they own them.
- Manual fixture directories are not auto-removed unless a wrapper script owns them; delete the fixture root when finished.

## Provisioning regression note

The fixture env file sets `PKCS11_PROVISIONING_REGRESSION=1`, but the provisioning regression still requires `PKCS11_SO_PIN` to be present. In practice:

- `InitToken` regression runs only when both `PKCS11_PROVISIONING_REGRESSION=1` and `PKCS11_SO_PIN` are available
- the test looks for a free or uninitialized SoftHSM slot before calling `InitToken`
- `InitToken` is treated as provisioning-only coverage, not a mandatory path for arbitrary modules
