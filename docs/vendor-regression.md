# Vendor regression lane

See also: `docs/luna-compatibility-audit.md` for the current Thales Luna-specific scope boundary and extension-gap audit.
See also: `docs/luna-vendor-extension-design.md` for the proposed package/boundary/loading strategy for future Luna-only `CA_*` support.

## Purpose

The vendor regression lane is the non-SoftHSM validation path for pre-provisioned PKCS#11 modules. It is intentionally opt-in and is meant to prove that the wrapper still behaves correctly against a real or vendor-specific backend without assuming SoftHSM-only semantics.

## Compatibility profiles

The vendor lane is profile-driven so the same script can describe different pre-provisioned module contracts without introducing vendor-specific test binaries.

### `baseline-rsa-aes`

This is the default vendor compatibility profile used by `eng/run-regression-tests.sh --use-existing-env` unless you override it.

What it expects:

- one token reachable via `PKCS11_MODULE_PATH` + `PKCS11_TOKEN_LABEL`
- one AES secret key usable for encrypt/decrypt
- one RSA keypair usable for sign/verify
- user login via `PKCS11_USER_PIN`

Defaulted search/behavior contract:

- `PKCS11_FIND_CLASS=secret`
- `PKCS11_FIND_KEY_TYPE=aes`
- `PKCS11_REQUIRE_ENCRYPT=true`
- `PKCS11_REQUIRE_DECRYPT=true`
- `PKCS11_SIGN_MECHANISM=0x00000040` (`CKM_RSA_PKCS`)
- `PKCS11_SIGN_FIND_CLASS=private`
- `PKCS11_SIGN_FIND_KEY_TYPE=rsa`
- `PKCS11_SIGN_REQUIRE_SIGN=true`
- `PKCS11_VERIFY_FIND_CLASS=public`
- `PKCS11_VERIFY_FIND_KEY_TYPE=rsa`
- `PKCS11_VERIFY_REQUIRE_VERIFY=true`
- `PKCS11_VERIFY_FIND_LABEL` defaults to `PKCS11_SIGN_FIND_LABEL`
- `PKCS11_VERIFY_FIND_ID_HEX` defaults to `PKCS11_SIGN_FIND_ID_HEX`

Required inputs you still need to provide:

- `PKCS11_MODULE_PATH`
- `PKCS11_TOKEN_LABEL`
- `PKCS11_USER_PIN`
- `PKCS11_FIND_LABEL`
- `PKCS11_SIGN_FIND_LABEL`

### `luna-rsa-aes`

This is the optional **Thales Luna-oriented** profile for the same existing vendor lane. It does **not** add Luna-only APIs or a separate Luna test suite; it simply documents and labels the standard PKCS#11 contract that maps cleanly onto the audited Luna scope.

Use it when you want to validate a prepared Luna partition/keyring manually or through the opt-in workflow-dispatch vendor lane.

What it expects:

- one Luna PKCS#11 module reachable via `PKCS11_MODULE_PATH`
- one target Luna partition/keyring reachable via `PKCS11_TOKEN_LABEL`
- one AES secret key usable for encrypt/decrypt
- one RSA keypair usable for `CKM_RSA_PKCS` sign/verify
- user login via `PKCS11_USER_PIN`

Defaulted search/behavior contract:

- inherits the same RSA/AES defaults as `baseline-rsa-aes`
- keeps `PKCS11_SIGN_MECHANISM=0x00000040` (`CKM_RSA_PKCS`) unless you intentionally override it
- keeps provisioning off unless `PKCS11_PROVISIONING_REGRESSION=1` is explicitly set

Recommended additional disambiguation inputs for Luna environments with repeated labels:

- `PKCS11_FIND_ID_HEX`
- `PKCS11_SIGN_FIND_ID_HEX`
- `PKCS11_VERIFY_FIND_LABEL`
- `PKCS11_VERIFY_FIND_ID_HEX`

Required inputs you still need to provide:

- `PKCS11_MODULE_PATH`
- `PKCS11_TOKEN_LABEL`
- `PKCS11_USER_PIN`
- `PKCS11_FIND_LABEL`
- `PKCS11_SIGN_FIND_LABEL`

Example env template:

- `eng/vendor-profiles/luna-rsa-aes.env.example`

### `baseline-rsa-aes` + provisioning

If you also want the provisioning/admin regression path, enable:

- `PKCS11_PROVISIONING_REGRESSION=1`
- `PKCS11_SO_PIN`

This turns on the `InitToken` provisioning regression in addition to the baseline lane.

## Capability-gated vs broken behavior

The vendor lane distinguishes these two cases:

- **Capability-gated**: the module does not expose a mechanism/flag combination needed for an optional regression path. These tests should be reported as skipped/capability-gated, not treated as hard failures.
- **Broken behavior**: required env contract is incomplete, expected seed objects are missing, or a supported path behaves incorrectly. These should fail the run.

`PKCS11_STRICT_REQUIRED=1` is used in the scripted regression lane so missing required env or object-contract drift fails loudly instead of silently reducing coverage.

## Luna profile expectations

The `luna-rsa-aes` profile is intentionally conservative. It means:

- use the existing vendor regression path against a prepared Luna environment
- validate standard `C_*` PKCS#11 behavior only
- keep Luna-only `CA_*` extension claims out of scope
- treat vendor capability differences as capability-gated unless the env/object contract itself is broken

### Standard checks you should expect to run

The existing regression suite stays intact. Against a Luna environment, that means the lane should normally cover standard checks such as:

- module initialize/finalize, slot/token enumeration, and session login/logout
- seeded-object discovery for the configured AES and RSA objects before the test suite starts
- digest and random generation/seed behavior
- AES encrypt/decrypt round-trips, multipart update/final semantics, and buffer-too-small behavior
- RSA sign/verify round-trips with `CKM_RSA_PKCS` plus invalid-signature behavior
- object search / attribute reads plus standard object create/copy/update/destroy flows
- standard generate/wrap/unwrap/derive/mechanism-matrix checks when the Luna policy + mechanism set exposes them
- standard admin/session flows such as `SetPin`, `InitPin`, `CloseAllSessions`, and optional `InitToken` when you explicitly enable the provisioning path

### Capability-gated or unsupported on Luna

Based on the completed audit, these should remain capability-gated, unsupported, or explicitly unverified for Luna rather than being described as blanket support:

- `C_WaitForSlotEvent`
- `C_GetFunctionStatus` / `C_CancelFunction`
- `C_SignRecover*` / `C_VerifyRecover*`
- `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`
- `C_GetOperationState` / `C_SetOperationState` on Luna keyrings (public docs indicate partitions are the safer expectation)
- PKCS#11 v3 interface discovery (`C_GetInterface*`), message APIs (`C_Message*`), `C_LoginUser`, and `C_SessionCancel` until a real Luna runtime proves them
- all Luna `CA_*` extension APIs, including extension replacements such as `CA_WaitForSlotEvent` and `CA_SessionCancel`

If one of the capability-gated checks is absent because the Luna runtime or token policy does not expose it, that should be interpreted as a skipped/capability-gated result, not as proof that the wrapper is broken.

## Recommended local usage

```bash
export PKCS11_USE_EXISTING_ENV=1
export PKCS11_VENDOR_PROFILE=baseline-rsa-aes
export PKCS11_MODULE_PATH='/path/to/vendor-pkcs11.so'
export PKCS11_TOKEN_LABEL='your-token-label'
export PKCS11_USER_PIN='your-pin'
export PKCS11_FIND_LABEL='existing-aes-label'
export PKCS11_SIGN_FIND_LABEL='existing-rsa-label'
./eng/run-regression-tests.sh --use-existing-env
```

Thales Luna-oriented usage:

```bash
cp eng/vendor-profiles/luna-rsa-aes.env.example /tmp/luna-rsa-aes.env
# fill in the copied file with your real library path / labels / PINs
set -a
source /tmp/luna-rsa-aes.env
set +a
./eng/run-regression-tests.sh --use-existing-env
```

For the optional workflow-dispatch vendor lane, set repository variable `VENDOR_PKCS11_PROFILE=luna-rsa-aes` together with the existing `VENDOR_PKCS11_*` variables/secrets from `docs/ci.md`. This keeps the Luna path opt-in and avoids introducing a baseline CI dependency on the Luna client.

Optional provisioning/admin path:

```bash
export PKCS11_PROVISIONING_REGRESSION=1
export PKCS11_SO_PIN='your-so-pin'
./eng/run-regression-tests.sh --use-existing-env
```
