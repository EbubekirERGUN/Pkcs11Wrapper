# Vendor regression lane

See also: `docs/luna-compatibility-audit.md` for the current Thales Luna-specific scope boundary and extension-gap audit.

## Purpose

The vendor regression lane is the non-SoftHSM validation path for pre-provisioned PKCS#11 modules. It is intentionally opt-in and is meant to prove that the wrapper still behaves correctly against a real or vendor-specific backend without assuming SoftHSM-only semantics.

## Compatibility profiles

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

Optional provisioning/admin path:

```bash
export PKCS11_PROVISIONING_REGRESSION=1
export PKCS11_SO_PIN='your-so-pin'
./eng/run-regression-tests.sh --use-existing-env
```
