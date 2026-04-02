# Vendor regression lane

See also: `docs/luna-integration.md` for the practical Luna client/module setup path across wrapper, admin panel, smoke, and vendor regression.
See also: `docs/luna-compatibility-audit.md` for the current Thales Luna-specific scope boundary and extension-gap audit.
See also: `docs/cloudhsm-integration.md` and `docs/cloudhsm-compatibility-audit.md` for the current AWS CloudHSM support boundary.
See also: `docs/azure-cloud-hsm-integration.md` and `docs/azure-cloud-hsm-compatibility-audit.md` for the current Azure Cloud HSM support boundary.
See also: `docs/google-cloud-hsm-integration.md` and `docs/google-cloud-hsm-compatibility-audit.md` for the current Google Cloud HSM / kmsp11 support boundary.
See also: `docs/ibm-cloud-hpcs-integration.md` and `docs/ibm-cloud-hpcs-compatibility-audit.md` for the current IBM Cloud Hyper Protect Crypto Services support boundary.
See also: `docs/oci-dedicated-kms-integration.md` and `docs/oci-dedicated-kms-compatibility-audit.md` for the current Oracle OCI Dedicated KMS support boundary.
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

## Why there is not yet a checked-in AWS CloudHSM profile

See also: `docs/cloudhsm-integration.md` and `docs/cloudhsm-compatibility-audit.md`.

AWS CloudHSM is now a documented target for the repo, but there is intentionally **no** checked-in `cloudhsm-*` vendor-regression profile yet.

Reason:

- AWS Client SDK 5 documents that read-only `C_OpenSession` is not supported
- AWS’s supported-API page does not currently list several operations assumed elsewhere in the broader repo/runtime surface, including `C_CopyObject`, `C_SetAttributeValue`, `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_GetOperationState`, and PKCS#11 v3-only paths
- the existing smoke/vendor-regression flow would need CloudHSM-specific capability gating before a profile could be described as reliable rather than misleading

So the current CloudHSM support slice is:

- strong documentation
- admin-panel readiness improvements
- explicit wrapper/admin setup guidance

rather than a premature vendor-lane profile that would overstate validation depth.

## Why there is not yet a checked-in Azure Cloud HSM profile

See also: `docs/azure-cloud-hsm-integration.md` and `docs/azure-cloud-hsm-compatibility-audit.md`.

Azure Cloud HSM is now a documented target for the repo, but there is intentionally **no** checked-in `azure-*` vendor-regression profile yet.

Reason:

- the direct PKCS#11 path depends on a prepared Azure host runtime that includes `azcloudhsm_client`, `azcloudhsm_resource.cfg`, `azcloudhsm_application.cfg`, `PO.crt`, and private-network reachability to the cluster
- Azure's reviewed public docs publish a broad standard PKCS#11 function table, but honest end-to-end validation still requires a live Azure Cloud HSM environment that was not available during issue #70
- Azure documents shared host-side client-session behavior, so a naive checked-in profile could mislead operators into expecting isolated local/CI semantics that are not guaranteed on a shared host
- Azure's Cloud-HSM-vs-Managed-HSM product boundary matters, and a checked-in vendor profile should not blur that by implying Azure Key Vault Managed HSM or broader Azure service-encryption scenarios are already covered by the current PKCS#11 lane
- the current generic vendor lane does not provision Azure networking, onboarding, SSH/bootstrap, or user synchronization state, so a checked-in profile would overstate operational maturity

So the current Azure support slice is:

- strong documentation
- admin-panel vendor-profile guidance
- explicit Azure Cloud HSM vs Azure Managed HSM boundary clarification

rather than a premature vendor-lane profile that would overstate validation depth.

## Why there is not yet a checked-in Google Cloud HSM profile

See also: `docs/google-cloud-hsm-integration.md` and `docs/google-cloud-hsm-compatibility-audit.md`.

Google Cloud HSM is now a documented target for the repo, but there is intentionally **no** checked-in `google-*` vendor-regression profile yet.

Reason:

- the official Google PKCS#11 path is **indirect** through `kmsp11` and Cloud KMS rather than a direct local HSM client/runtime contract
- kmsp11 requires a real config file plus real Google authentication/IAM, so a checked-in profile would risk implying repeatable local/CI coverage that the repo cannot honestly provide without live cloud access
- Google's documented function table intentionally excludes operations assumed elsewhere in the broader vendor lane, including `C_CreateObject`, `C_CopyObject`, `C_SetAttributeValue`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`, `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_Digest*`, and operation-state paths
- kmsp11 key creation depends on Google-specific `CKA_KMS_*` template attributes, which the current generic vendor lane does not model cleanly
- the current wrapper/admin path depends on host-level `KMS_PKCS11_CONFIG` rather than a repo-managed per-profile initialize-argument channel

So the current Google support slice is:

- strong documentation
- admin-panel readiness improvements and guardrails
- explicit wrapper/admin setup guidance

rather than a premature vendor-lane profile that would overstate validation depth.

## Why there is not yet a checked-in IBM Cloud HPCS profile

See also: `docs/ibm-cloud-hpcs-integration.md` and `docs/ibm-cloud-hpcs-compatibility-audit.md`.

IBM Cloud Hyper Protect Crypto Services is now a documented target for the repo, but there is intentionally **no** checked-in `ibm-*` vendor-regression profile yet.

Reason:

- the direct PKCS#11 path depends on a real HPCS instance, EP11 endpoint reachability, `grep11client.yaml`, keystore UUIDs, and IBM IAM service-ID/API-key setup
- IBM's reviewed public docs publish a stronger PKCS#11 function table than several other cloud vendors, but honest end-to-end validation still requires a live cloud environment that was not available during issue #69
- optional authenticated-keystore passwords and optional EP11 mutual TLS add more runtime/bootstrap state that the current generic vendor lane cannot verify offline
- IBM also publishes a separate GREP11 gRPC path, and a checked-in vendor profile should not blur that boundary by implying all IBM HPCS integration styles are already covered by the current PKCS#11 lane
- IBM's reviewed direct-client packaging is Linux-only for the current repo boundary, so a checked-in cross-platform vendor profile would overstate maturity

So the current IBM support slice is:

- strong documentation
- admin-panel vendor-profile guidance
- explicit direct-PKCS#11-vs-GREP11 boundary clarification

rather than a premature vendor-lane profile that would overstate validation depth.

## Why there is not yet a checked-in OCI Dedicated KMS profile

See also: `docs/oci-dedicated-kms-integration.md` and `docs/oci-dedicated-kms-compatibility-audit.md`.

Oracle OCI Dedicated KMS is now a documented target for the repo, but there is intentionally **no** checked-in `oci-*` vendor-regression profile yet.

Reason:

- the direct PKCS#11 path depends on a real OCI HSM cluster, client certificates/keys, and a running `client_daemon`
- Oracle's reviewed public docs confirm the Linux PKCS#11 packaging path, login model, and some mechanism families, but they do **not** publish the kind of exhaustive supported-API matrix that would justify broad repo claims from docs alone
- Oracle's reviewed Windows docs describe CNG/KSP rather than a Windows PKCS#11 path for the current repo boundary
- no live OCI environment was available during issue #68 to prove the existing vendor lane contract end to end

So the current OCI support slice is:

- strong documentation
- admin-panel vendor-profile guidance
- explicit direct-vs-indirect Oracle product-boundary clarification

rather than a premature vendor-lane profile that would overstate validation depth.

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
