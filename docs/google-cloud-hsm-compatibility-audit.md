# Google Cloud HSM PKCS#11 compatibility audit

See also:

- `docs/google-cloud-hsm-integration.md` for the practical wrapper/admin-panel setup path
- `docs/compatibility-matrix.md` for the repo-wide support summary
- `docs/vendor-regression.md` for the current vendor-lane boundary

## Scope

This document audits **publicly documented Google Cloud HSM / Cloud KMS PKCS#11 compatibility** against the current `Pkcs11Wrapper` repository.

It is intentionally conservative:

- it distinguishes **Google's documented kmsp11 PKCS#11 subset** from the broader PKCS#11 surface exposed by the wrapper
- it separates **already good repo alignment** from **abstraction-boundary mismatches** and **real-runtime-only validation**
- it does **not** claim support that requires a real Google Cloud environment when no live Cloud KMS / Cloud HSM access was available during issue #67

## Google public references reviewed

- Cloud HSM overview: <https://cloud.google.com/kms/docs/hsm>
- Cloud KMS PKCS#11 library reference page: <https://cloud.google.com/kms/docs/reference/pkcs11-library>
- kmsp11 user guide: <https://github.com/GoogleCloudPlatform/kms-integrations/blob/master/kmsp11/docs/user_guide.md>
- Google authentication getting started: <https://cloud.google.com/docs/authentication/getting-started>
- latest kmsp11 release assets reviewed during this issue: `libkmsp11.so` / `kmsp11.dll` from the `GoogleCloudPlatform/kms-integrations` release page

## Repository areas reviewed

### Core wrapper

- `src/Pkcs11Wrapper`
- `src/Pkcs11Wrapper.Native`

### Admin surface

- `src/Pkcs11Wrapper.Admin.Application`
- `src/Pkcs11Wrapper.Admin.Web`

### Runtime / validation / docs

- `docs/vendor-regression.md`
- `docs/compatibility-matrix.md`
- `README.md`

## Executive summary

The current repo is in a **good position for standard kmsp11 usage**, but the support path is importantly different from AWS CloudHSM or vendor client SDK integrations.

The most important compatibility conclusions are:

1. **The right support boundary is indirect PKCS#11 via kmsp11, not direct Google HSM client integration.**
   - Google Cloud HSM lives behind Cloud KMS.
   - The official PKCS#11 story is Google's `kmsp11` adapter.
   - So repo support should be described as **Cloud KMS / Cloud HSM through kmsp11**, not as direct hardware-client integration.

2. **The wrapper is already structurally compatible with the documented kmsp11 surface.**
   - Standard module loading, slot enumeration, object search, attribute reads, crypto calls, and raw numeric attribute handling all line up with Google's documented path.
   - No new Google-specific wrapper assembly is required for the first useful slice.

3. **The admin panel needed honesty guardrails more than a new runtime shim.**
   - kmsp11 intentionally does not support `C_CreateObject`, `C_CopyObject`, `C_SetAttributeValue`, wrap/unwrap/derive, PIN admin, digest, operation-state, or wait-for-slot-event.
   - kmsp11 key generation also depends on Google-specific `CKA_KMS_*` template attributes.
   - So the current generic admin key-management forms should not be advertised as fully Google-ready.

4. **The current repo has one meaningful abstraction-boundary gap: kmsp11 config-path delivery.**
   - Google documents `C_Initialize` `pReserved` or `KMS_PKCS11_CONFIG` for config-path delivery.
   - The current wrapper/admin path does not yet expose `pReserved` directly.
   - Therefore the practical support path today is host-level `KMS_PKCS11_CONFIG`.

5. **A real Google Cloud environment is still required for honest end-to-end validation.**
   - This issue improves documentation and admin readiness.
   - It does not pretend that compile-time work equals real Cloud KMS / Cloud HSM proof.

## Compatibility assessment

| Google / kmsp11 area | Google public documentation | Current repo status | Assessment |
| --- | --- | --- | --- |
| Core module lifecycle (`C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`) | Documented as supported | Fully wrapped in core | **Already good** |
| Slot / token / mechanism enumeration | Documented as supported | Fully wrapped and used by admin tooling | **Already good** |
| `C_OpenSession` / `C_GetSessionInfo` / `C_Login` / `C_Logout` / `C_CloseSession` / `C_CloseAllSessions` | Documented as supported; `CKF_SERIAL_SESSION` required; login optional and PIN ignored | Fully wrapped; admin/runtime can already use this shape | **Already good with kmsp11-specific semantics** |
| Config-path delivery (`pReserved` or `KMS_PKCS11_CONFIG`) | Documented by Google | Host env path works now; direct `pReserved` path not exposed in current managed API | **Supported through env-var path; partial abstraction mismatch** |
| `C_FindObjects*` / `C_GetAttributeValue` / `C_DestroyObject` | Documented as supported | Wrapped in core; used by admin flows | **Already good** |
| Sign / verify / encrypt / decrypt | Documented as supported for supported Cloud KMS-backed algorithms | Wrapped in core; admin lab can drive these generically | **Already good, but requires real-runtime validation** |
| `C_GenerateKey` / `C_GenerateKeyPair` | Documented as supported with `CKA_KMS_*` template rules | Wrapper can carry raw attrs; current generic admin forms do not model those attrs | **Wrapper-capable, admin abstraction not yet vendor-aware** |
| `C_GenerateRandom` | Documented as supported | Wrapped in core | **Already good** |
| `C_CreateObject` | Documented as unsupported | Wrapper/admin support exists generically | **Do not assume on Google** |
| `C_CopyObject` | Documented as unsupported | Wrapper/admin support exists generically | **Do not assume on Google** |
| `C_SetAttributeValue` | Documented as unsupported | Wrapper/admin support exists generically | **Do not assume on Google** |
| `C_GetObjectSize` | Documented as unsupported | Wrapper/admin support exists generically | **Do not assume on Google** |
| `C_WrapKey` / `C_UnwrapKey` / `C_DeriveKey` | Documented as unsupported | Wrapper/admin support exists generically | **Do not assume on Google** |
| `C_Digest*` | Documented as unsupported | Wrapper/lab support exists generically | **Do not assume on Google** |
| `C_GetOperationState` / `C_SetOperationState` | Documented as unsupported | Wrapper support exists generically | **Do not assume on Google** |
| `C_InitToken` / `C_InitPIN` / `C_SetPIN` | Documented as unsupported | Wrapper/admin support exists generically | **Do not assume on Google** |
| `C_WaitForSlotEvent` / `C_GetFunctionStatus` / `C_CancelFunction` | Documented as unsupported | Wrapper support exists generically | **Treat as unavailable / unclaimed** |
| PKCS#11 v3-only interfaces (`C_GetInterface*`, `C_Message*`, `C_LoginUser`, `C_SessionCancel`) | Not part of the documented kmsp11 v2.40 story reviewed here | Wrapper supports them generically | **Unclaimed for Google** |

## Where compatibility is already good

### 1. Standard `C_*` wrapper architecture matches Google's published path

The repo already exposes the standard Cryptoki surface that Google documents for kmsp11.

That means the first useful Google slice does **not** require a dedicated Google wrapper package just to consume the documented standard surface.

### 2. Explicit module-path loading is the right operational model

`Pkcs11Wrapper` already expects an explicit library path.

That matches kmsp11 well because Google expects a host-local library plus host-local config/auth environment rather than a repo-managed provisioning step.

### 3. Raw numeric attribute/mechanism types are enough for the first wrapper slice

The wrapper's numeric PKCS#11 types can carry raw values, which matters because Google documents vendor-specific key-generation attributes such as `CKA_KMS_ALGORITHM`, `CKA_KMS_PROTECTION_LEVEL`, and `CKA_KMS_CRYPTO_KEY_BACKEND`.

That keeps wrapper-level Google support plausible even before higher-level helper polish exists.

### 4. The admin panel can already serve as a consumer/diagnostics surface

Once kmsp11 is installed and the host provides config/auth correctly, the admin panel is already a reasonable fit for:

- device registration
- connection testing
- slot/mechanism inventory
- object discovery
- read-oriented inspection
- selected lab diagnostics over the documented kmsp11 surface

## Where compatibility is capability-gated or future work

### 1. Google support is not a direct-HSM integration story

This is the biggest conceptual difference from other vendors.

The repo should not talk about Google Cloud HSM the way it talks about Luna or AWS client runtimes. The actual boundary is:

- `Pkcs11Wrapper` / admin panel -> **kmsp11**
- kmsp11 -> **Cloud KMS**
- Cloud KMS protection level -> **Cloud HSM**

That means control-plane and auth/setup boundaries remain fundamentally outside this repo.

### 2. The current admin key-management forms are not a clean fit for Google generation

Google documents `C_GenerateKey` / `C_GenerateKeyPair`, but with strong template constraints:

- `CKA_LABEL` is required
- `CKA_KMS_ALGORITHM` is required
- optional Google-specific attributes affect protection-level/backend behavior
- for key-pair generation, the public key template must not be specified

The wrapper can express these at the raw PKCS#11 layer, but the current admin AES/RSA forms are generic token-oriented forms. So the repo should not claim Google-ready admin generation from docs alone.

### 3. Generic import/copy/edit flows are the wrong abstraction for kmsp11

Google's kmsp11 function table explicitly marks these as unsupported:

- `C_CreateObject`
- `C_CopyObject`
- `C_SetAttributeValue`

So the repo should treat generic import/copy/edit as **Google-incompatible on purpose**, not as “maybe works if we're lucky.”

### 4. Config-path delivery is only partially modeled in the wrapper today

Google documents two supported config-delivery methods:

- `pReserved` in `C_Initialize`
- `KMS_PKCS11_CONFIG`

The repo currently only has a clean practical story for the second one.

That is good enough for the first useful slice, but it is still a real abstraction boundary to keep visible in docs.

### 5. kmsp11 caching changes operational expectations

Google documents that kmsp11 reads and caches configured key-ring contents during initialization.

Repo implication:

- `C_Initialize` cost scales with configured inventory
- Cloud KMS changes are not necessarily instantly visible
- admin/runtime behavior may look “stale” unless refresh/reinitialize behavior is understood

## Google-specific operational constraints that affect repo design

### 1. Login is not a real security boundary in kmsp11

Google documents that:

- login is optional
- only `CKU_USER` is accepted
- any supplied PIN is ignored

Repo implication:

- generic UI patterns that assume a meaningful token PIN should be treated carefully
- docs should describe auth as **Google service-account/IAM driven**, not token-PIN driven

### 2. Key visibility depends on Cloud KMS metadata, not local-token semantics

Google documents that only keys with supported purpose, protection level, and enabled state are surfaced.

Repo implication:

- object inventory depends on Cloud KMS policy/state
- “missing objects” can be a Cloud KMS configuration issue rather than a PKCS#11 parsing/runtime issue

### 3. Admin and wrapper users should expect Cloud KMS identifiers to leak into PKCS#11 identity

Google documents that:

- `CKA_LABEL` maps to the Cloud KMS CryptoKey identifier
- `CKA_ID` maps to the full CryptoKeyVersion resource name

Repo implication:

- long IDs and cloud-resource-shaped identifiers are normal
- lookup-by-label/ID remains viable, but should be understood in Cloud KMS terms rather than token-object terms

## What could be validated locally in issue #67

Without a real Google Cloud environment, this issue could validate:

- documentation correctness against Google public docs
- compile/build correctness of the new admin Google guardrails
- compile/build correctness of the new Google vendor-profile wiring
- unit-test coverage of the Google vendor-profile catalog mapping
- repo-level analysis of the wrapper/admin abstraction boundary

## What could not be validated honestly in issue #67

Without a live Google-authenticated environment, this issue could **not** honestly validate:

- real kmsp11 initialization against a real config file and key-ring inventory
- real IAM/auth success and failure behavior
- real Linux/Windows deployment quirks beyond the published prerequisites
- real Cloud HSM-backed key visibility and operation success
- real `C_GenerateKey` / `C_GenerateKeyPair` behavior with Google-specific templates
- real admin-panel end-to-end behavior against Google Cloud services
- real vendor-regression or smoke success against kmsp11 and Cloud HSM-backed keys

## Practical conclusion

The current repo should describe Google Cloud HSM support as:

- **good candidate for standard PKCS#11 integration via kmsp11**
- **wrapper-compatible for Google's documented standard subset**
- **admin-panel-ready enough for device registration, inspection, and honest guardrails**
- **not a blanket claim for every PKCS#11 method the wrapper exposes**
- **not yet live-validated without real Google Cloud access**

That is the honest and useful first support slice for issue #67.
