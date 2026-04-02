# AWS CloudHSM PKCS#11 compatibility audit

See also:

- `docs/cloudhsm-integration.md` for the practical wrapper/admin-panel setup path
- `docs/compatibility-matrix.md` for the repo-wide support summary
- `docs/vendor-regression.md` for the current vendor-lane boundary

## Scope

This document audits **publicly documented AWS CloudHSM PKCS#11 compatibility** against the current `Pkcs11Wrapper` repository.

It is intentionally conservative:

- it distinguishes **documented CloudHSM standard PKCS#11 support** from **unsupported/unlisted PKCS#11 surfaces**
- it separates **already good repo alignment** from **capability-gated** or **unvalidated** areas
- it does **not** claim support that requires a real AWS CloudHSM runtime when no live cluster was available during issue #66

## AWS public references reviewed

- AWS CloudHSM PKCS#11 library overview: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html>
- PKCS#11 install path / SDK 5 runtime layout: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html>
- cluster bootstrap / certificate requirements: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/cluster-connect.html>
- Client SDK 5 configure-tool parameters/examples: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/configure-tool-params5.html>
- PKCS#11 authentication model: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-pin.html>
- supported API operations: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-apis.html>
- supported mechanisms: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html>
- multi-slot behavior: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-configs-multi-slot.html>
- known issues: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/ki-pkcs11-sdk.html>
- SDK 3 -> 5 migration notes: <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-migrate-to-sdk-5.html>
- latest release page reviewed during this issue: Client SDK **5.17.1**

## Repository areas reviewed

### Core wrapper

- `src/Pkcs11Wrapper`
- `src/Pkcs11Wrapper.Native`

### Admin surface

- `src/Pkcs11Wrapper.Admin.Application`
- `src/Pkcs11Wrapper.Admin.Web`

### Runtime / validation / docs

- `samples/Pkcs11Wrapper.Smoke`
- `docs/vendor-regression.md`
- `docs/smoke.md`
- `docs/compatibility-matrix.md`
- `README.md`

## Executive summary

The current repo is in a **good position for standard AWS CloudHSM PKCS#11 usage** when the scenario stays inside the AWS-documented Client SDK 5 contract.

The most important compatibility conclusions are:

1. **Standard PKCS#11 usage is the right support path.**
   - The wrapper already models the standard `C_*` surface AWS documents for Client SDK 5.
   - No separate AWS-specific extension package is required for the first useful slice.

2. **CloudHSM’s session semantics are the biggest immediate repo mismatch.**
   - AWS documents that SDK 5 rejects read-only `C_OpenSession`.
   - Generic PKCS#11 tooling often assumes RO-by-default browse sessions.
   - This issue now fixes that mismatch in the admin panel by retrying a failed RO open as RW.

3. **Some current repo admin/runtime features should not be described as CloudHSM-ready yet.**
   - AWS’s supported-API page does not list several operations used elsewhere in the repo, such as `C_CopyObject`, `C_SetAttributeValue`, `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_GetOperationState`, `C_SetOperationState`, and PKCS#11 v3-only features.
   - Those paths must remain unclaimed, capability-gated, or future work for CloudHSM.

4. **Vendor-defined mechanisms/types exist, but first-class wrapper coverage is partial.**
   - CloudHSM documents vendor-defined AES-GCM / AES-wrap mechanisms and vendor-defined KDF types.
   - The wrapper can still carry raw numeric mechanism/type values, but there is not yet a polished first-class CloudHSM-specific helper layer.

5. **A real CloudHSM runtime is still required for honest end-to-end validation.**
   - This issue improves readiness and documentation, but does not pretend that compile-time work equals live-cluster proof.

## Compatibility assessment

| CloudHSM area | AWS public documentation | Current repo status | Assessment |
| --- | --- | --- | --- |
| Core module lifecycle (`C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`) | Documented as supported | Fully wrapped in core | **Already good** |
| Slot / token / mechanism enumeration | Documented as supported | Fully wrapped and used by admin/smoke tooling | **Already good** |
| `C_OpenSession` / `C_GetSessionInfo` / `C_Login` / `C_Logout` / `C_CloseSession` / `C_CloseAllSessions` | Documented as supported, with RW-session requirement | Fully wrapped; admin panel now includes RO->RW compatibility retry | **Already good with CloudHSM-specific caveat** |
| PKCS#11 login credential format | AWS documents `username:password` CU login | Wrapper/admin can pass arbitrary bytes; docs now capture CloudHSM semantics | **Already good once documented** |
| `C_CreateObject` / `C_DestroyObject` / `C_FindObjects*` / `C_GetAttributeValue` | Documented as supported | Wrapped in core; used heavily by admin flows | **Already good** |
| `C_GenerateKey` / `C_GenerateKeyPair` / `C_WrapKey` / `C_UnWrapKey` / `C_DeriveKey` | Documented as supported | Wrapped in core; admin panel already exposes many of these paths | **Already good for standard documented cases** |
| Single-part sign/verify and encrypt/decrypt | Documented as supported | Wrapped in core; admin lab supports them | **Already good** |
| Multipart digest/sign/encrypt/decrypt | Supported APIs and mechanisms are documented, but known-issues page warns about multipart hashing/signing history and AES-GCM caveats | Wrapped in core; smoke/lab can drive them generically | **Treat as version-sensitive; requires real-runtime validation** |
| `C_CopyObject` | Not listed by AWS supported-API page reviewed here | Wrapper/admin support exists generically | **Do not assume on CloudHSM** |
| `C_SetAttributeValue` | Not listed by AWS supported-API page reviewed here | Wrapper/admin support exists generically | **Do not assume on CloudHSM** |
| `C_GetObjectSize` | Not listed by AWS supported-API page reviewed here | Wrapper/admin support exists generically | **Do not assume on CloudHSM** |
| `C_InitToken` / `C_InitPIN` / `C_SetPIN` | Not listed by AWS supported-API page reviewed here | Wrapper/admin support exists generically | **Do not assume on CloudHSM** |
| `C_GetOperationState` / `C_SetOperationState` | Not listed by AWS supported-API page reviewed here | Wrapper/smoke support exists generically | **Do not assume on CloudHSM** |
| `C_WaitForSlotEvent` | Not listed by AWS supported-API page reviewed here | Wrapper exposes it generically | **Treat as unavailable / unclaimed** |
| PKCS#11 v3 interface discovery (`C_GetInterface*`) | Not listed by AWS supported-API page reviewed here | Wrapper supports it generically | **Unclaimed for CloudHSM** |
| PKCS#11 v3 message APIs (`C_Message*`) | Not listed by AWS supported-API page reviewed here | Wrapper supports them generically | **Unclaimed for CloudHSM** |
| `C_LoginUser` / `C_SessionCancel` | Not listed by AWS supported-API page reviewed here | Wrapper supports them generically | **Unclaimed for CloudHSM** |
| Vendor-defined AES-GCM / AES-wrap mechanisms | AWS documents them | Numeric mechanism IDs are possible; first-class helper polish is partial | **Potentially usable, but not yet a polished named helper path** |
| Vendor-defined KDF types for ECDH | AWS documents them | Numeric representation is possible; structured/live validation absent here | **Potentially usable, but requires real-runtime proof** |

## Where compatibility is already good

### 1. Standard `C_*` wrapper architecture matches the CloudHSM support path

The repo already exposes the standard Cryptoki surface that AWS documents for Client SDK 5.

That means the first useful CloudHSM path does **not** require a new AWS-specific wrapper assembly just to get started.

### 2. Explicit module-path loading is the right operational model

`Pkcs11Wrapper` already expects an explicit library path. That matches CloudHSM well because AWS requires a host-local installed SDK/runtime and host-local bootstrap/configuration.

### 3. Numeric mechanism/type escape hatches help with CloudHSM vendor diversity

The wrapper’s numeric PKCS#11 types can carry raw values, which matters because CloudHSM documents vendor-defined mechanisms and KDF types beyond the common standard constants.

### 4. The admin panel now addresses the biggest immediate CloudHSM mismatch

This issue adds a compatibility improvement in `HsmAdminService` so a read-only session request that fails with `CKR_FUNCTION_FAILED` is retried as read-write.

That directly improves the CloudHSM path for:

- session opening
- key browsing
- object detail inspection
- PKCS#11 Lab browse/inspect operations

## Where compatibility is capability-gated or future work

### 1. CloudHSM does not look like a full fit for every current admin feature

Because AWS’s supported-API documentation does not currently list `C_CopyObject`, `C_SetAttributeValue`, or `C_GetObjectSize`, the repo should not describe object-copy/edit/detail-size flows as broadly CloudHSM-supported.

This does **not** mean those methods can never work on any runtime build. It means the repo should not claim them from public docs alone.

### 2. Token/PIN administration should stay unclaimed

The supported-API page reviewed here does not list:

- `C_InitToken`
- `C_InitPIN`
- `C_SetPIN`

So generic repo support for those calls must not be translated into CloudHSM support claims.

### 3. Operation-state and wait-for-slot-event should stay out of the CloudHSM promise

The supported-API page reviewed here does not list:

- `C_GetOperationState`
- `C_SetOperationState`
- `C_WaitForSlotEvent`

That means:

- smoke/sample paths that assume those features are not a clean CloudHSM validation story today
- CloudHSM should not be added casually to the existing vendor lane without additional capability gating

### 4. PKCS#11 v3 should remain unclaimed for CloudHSM

The repo supports optional PKCS#11 v3 interfaces, but AWS’s supported-API page reviewed for issue #66 does not list:

- `C_GetInterface*`
- `C_LoginUser`
- `C_SessionCancel`
- `C_Message*`

So the correct current stance is:

- wrapper support exists generically
- CloudHSM support is **not** claimed from public docs

### 5. Multipart behavior requires real-version validation

AWS documentation is mixed here:

- multipart entry points appear in the supported-API page
- the known-issues page also documents multipart hashing/signing caveats and AES-GCM limitations

The safe conclusion is:

- do not claim multipart behavior from documentation alone
- validate against the exact Client SDK 5 version you deploy

## CloudHSM-specific operational constraints that affect repo design

### 1. Read-write sessions are mandatory

This is the most important practical constraint.

AWS documents that read-only session opens fail with `CKR_FUNCTION_FAILED`.

Repo implications:

- generic RO browse flows need adaptation
- admin panel required a compatibility fix
- future CloudHSM-specific smoke/regression work must be careful not to assume RO defaults

### 2. Handles are session-specific

AWS’s migration notes document session-specific handles in SDK 5.

Repo implication:

- object lookup by label/ID/class is the safer long-term pattern
- persistent cached-handle assumptions should be avoided for CloudHSM

### 3. Vendor-defined mechanisms/types exist but need real-runtime proof

AWS documents vendor-defined items such as:

- `CKM_CLOUDHSM_AES_GCM`
- `CKM_CLOUDHSM_AES_KEY_WRAP_*`
- vendor-defined ECDH KDF types

Repo implication:

- raw numeric use is possible
- polished named helpers and structured validation are still future work

## What could be validated locally in issue #66

Without a real CloudHSM runtime, this issue could validate:

- documentation correctness against AWS public docs
- compile/build correctness of the admin-panel compatibility change
- unit-test coverage of the RO->RW retry decision logic
- AWS vendor-profile catalog wiring in the admin panel

## What could not be validated honestly in issue #66

Without a live AWS CloudHSM environment, this issue could **not** honestly validate:

- actual SDK installation path resolution on Linux/Windows
- real cluster bootstrap/configuration
- real CU login behavior
- real slot/token/mechanism exposure
- real multipart behavior on Client SDK 5.17.1 or any other deployed version
- real create/generate/wrap/unwrap compatibility under a CloudHSM policy
- real admin-panel end-to-end behavior against AWS hardware
- real smoke or vendor-regression success on CloudHSM

## Practical conclusion

The current repo should describe AWS CloudHSM support as:

- **good candidate for standard PKCS#11 integration via Client SDK 5**
- **admin-panel-ready enough for device registration, inspection, and standard diagnostics, with RO->RW compatibility fallback now added**
- **not yet live-validated in CI or local automation without a real CloudHSM environment**
- **not a blanket claim for every PKCS#11 method the wrapper exposes**

That is the honest and useful first support slice for issue #66.
