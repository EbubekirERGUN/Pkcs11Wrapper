# Thales Luna PKCS#11 compatibility audit

## Scope

This document audits **publicly documented Thales Luna PKCS#11 compatibility** against the current `Pkcs11Wrapper` repository.

It is intentionally conservative:

- it distinguishes **standard PKCS#11 compatibility** from **Luna-only extension compatibility**
- it separates **already good support** from **capability-gated support**
- it does **not** claim support for Luna-only APIs that the wrapper does not bind today
- it uses only public Luna documentation reviewed during issue #30

## Public Luna references reviewed

- Thales Luna PKCS#11 compliance table: <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/pkcs11/pkcs11_standard.htm>
- Thales Luna extensions index (`CA_*` APIs): <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/extensions/safenet_extensions.htm>
- Thales Luna mechanism summary: <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/mechanism_summary_7-9-2.htm>
- Thales Luna `p11Sample` documentation: <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/pkcs11/pkcs11_sample.htm>

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
- `docs/development.md`
- `README.md`

## Executive summary

The current wrapper is in a **good position for Luna standard PKCS#11 usage** because it already exposes the core `C_*` Cryptoki surface needed for normal session, object, key, encrypt/decrypt, sign/verify, wrap/unwrap, derive, and token-management flows.

The main compatibility boundaries are:

1. **Luna standard PKCS#11 support is stronger than Luna extension support.**
   - The wrapper binds the standard `C_GetFunctionList` table and optional PKCS#11 v3 `C_GetInterface*` exports.
   - It does **not** bind the Luna extension table obtained through `CA_GetFunctionList`.

2. **Many Luna scenarios are compatible only when they stay inside standard `C_*` calls.**
   - This includes most ordinary partition-based RSA/AES/ECC operations and object management.
   - It does not include Luna-specific admin/control flows such as cloning, HA control, container/keyring management, PED/MofN workflows, STC/STM, and other `CA_*` entry points.

3. **The wrapper is generic enough to work with many Luna mechanisms and attributes numerically, but helper coverage is intentionally selective.**
   - `Pkcs11MechanismType`, `Pkcs11AttributeType`, `Pkcs11ObjectClass`, and `Pkcs11KeyType` all allow raw numeric values.
   - This is good for standard or vendor-defined constants.
   - However, first-class helper constants and structured parameter marshalling only cover a subset of mechanisms today.

4. **Public Luna docs reviewed here do not confirm PKCS#11 v3 interface/message exports.**
   - The wrapper supports `C_GetInterface*`, `C_Message*`, `C_LoginUser`, and `C_SessionCancel`.
   - Those paths should be treated as **capability-gated / unverified for Luna** until validated against an actual Luna runtime that exports them.

## Compatibility assessment

| Luna area | Public Luna documentation | Current repo status | Assessment |
| --- | --- | --- | --- |
| Core module lifecycle (`C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`) | Documented as supported on Luna partitions and keyrings | Fully wrapped in core + exercised by smoke/regression/docs | **Already good** |
| Slot/token/mechanism enumeration | Documented as supported | Fully wrapped and exposed by admin diagnostics and smoke tooling | **Already good** |
| Token/session lifecycle (`C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_Login`, `C_Logout`) | Documented as supported | Wrapped in core and surfaced in admin/runtime tooling | **Already good** |
| Object lifecycle (`C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_GetObjectSize`, `C_GetAttributeValue`, `C_SetAttributeValue`, `C_FindObjects*`) | Documented as supported | Wrapped in core; admin panel and lab depend on it heavily | **Already good** |
| Single-part and multipart crypto (`C_Encrypt*`, `C_Decrypt*`, `C_Digest*`, `C_Sign*`, `C_Verify*`) | Mainline functions documented as supported | Wrapped in core; validated heavily with SoftHSM; vendor lane can exercise standard flows | **Already good for standard Luna paths** |
| Key management (`C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`) | Documented as supported; Luna notes `C_UnwrapKey` support for `CKA_UNWRAP_TEMPLATE` | Wrapped in core; smoke/vendor lane already exercises generate/wrap/unwrap/derive | **Already good for standard Luna paths** |
| `C_WaitForSlotEvent` | Public Luna compliance table marks it unsupported | Wrapper exposes the standard call only | **Capability-gated / effectively unavailable on Luna standard path** |
| `C_GetOperationState` / `C_SetOperationState` | Supported on Luna partitions, not on Luna keyrings | Wrapper exposes both; smoke already treats operation-state as capability-dependent | **Good on partitions, capability-gated on keyrings** |
| `C_SignRecover*`, `C_VerifyRecover*`, `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` | Public Luna compliance table marks them unsupported | Wrapper exposes standard surfaces where implemented, but Luna should not be assumed to support them | **Capability-gated / do not rely on Luna support** |
| `C_GetFunctionStatus` / `C_CancelFunction` | Public Luna compliance table marks them unsupported; Luna also documents no parallel sessions | Wrapper exposes capability-gated probes (`TryGetFunctionStatus`, `TryCancelFunction`) | **Capability-gated / expected absent on Luna** |
| PKCS#11 v3 interface discovery (`C_GetInterface*`) | Not confirmed in the public Luna docs reviewed here | Wrapper supports it and validates it against a shim | **Unverified for Luna; do not claim without runtime proof** |
| PKCS#11 v3 message APIs (`C_Message*`) | Not confirmed in the public Luna docs reviewed here | Wrapper supports them and validates them against a shim | **Unverified for Luna; do not claim without runtime proof** |
| `C_LoginUser` / standard `C_SessionCancel` | Not confirmed in the public Luna docs reviewed here | Wrapper supports them via v3 interface discovery | **Unverified for Luna; do not claim without runtime proof** |
| Luna mechanism catalog beyond the small built-in constant set (for example ECIES, EdDSA, SHA-3 RSA variants, BIP32, ML-DSA entries shown in the public mechanism summary) | Public mechanism summary lists many mechanisms beyond the wrapper's named constants | Core types accept raw numeric mechanism IDs; admin lab accepts hex mechanism input | **Often usable, but helper coverage is partial** |
| Luna extension table via `CA_GetFunctionList` | Public docs clearly expose a large `CA_*` extension surface | Wrapper does not load or project `CA_GetFunctionList` / `CA_*` entry points | **Vendor-extension-only and not supported today** |
| Luna extension replacements such as `CA_WaitForSlotEvent` / `CA_SessionCancel` | Public extensions page lists them | Wrapper does not bind `CA_*` functions | **Vendor-extension-only and not supported today** |
| Luna cloning / HA / PED / MofN / container / STC / STM / policy-admin extension families | Public extensions page lists these families extensively | No direct binding in core, admin, or validation tooling | **Vendor-extension-only and not supported today** |

## Where compatibility is already good

### 1. Standard Luna partition-oriented PKCS#11 workflows

The current wrapper is already well aligned with the public Luna standard compliance table for the mainstream `C_*` surface:

- module initialization/finalization
- slot and token enumeration
- login/logout and session management
- object search and attribute reads
- object creation/copy/update/destroy
- encrypt/decrypt
- digest/sign/verify
- key generation, wrap/unwrap, derive
- random generation

This is the most important compatibility result. For ordinary Luna partition usage that stays inside standard PKCS#11, the repository already has the right architectural shape.

### 2. Generic numeric escape hatches help with vendor diversity

The wrapper does **not** force callers to stay inside a closed enum set:

- `Pkcs11MechanismType` accepts arbitrary numeric values
- `Pkcs11AttributeType` accepts arbitrary numeric values
- `Pkcs11ObjectClass` accepts arbitrary numeric values
- `Pkcs11KeyType` accepts arbitrary numeric values

That matters for Luna because the public mechanism catalog is broader than the handful of named constants currently exposed in `Pkcs11MechanismTypes`, and vendor-defined attributes/constants can still be represented numerically.

### 3. Admin diagnostics are more flexible than the curated admin workflows

The admin panel's **PKCS#11 Lab** is already the best current Luna exploration surface because it accepts:

- mechanism type as hex or decimal text
- raw attribute type input as hex or decimal text
- raw key/object lookup filters

This makes the lab materially more Luna-friendly than the curated admin pages, which intentionally focus on common standard objects and attributes.

### 4. Existing runtime tooling can exercise standard Luna flows

The existing vendor lane is already useful for Luna standard validation:

- `docs/vendor-regression.md`
- `docs/smoke.md`
- `samples/Pkcs11Wrapper.Smoke`

If a Luna library path, token label, PIN, and seed AES/RSA objects are provided, the repo already has a reasonable standard-PKCS#11 validation path without adding Luna-specific code first.

## Where compatibility is capability-gated

### 1. Luna-documented standard gaps

The public Luna compliance table explicitly marks some standard functions as unsupported. The wrapper can expose those calls, but Luna compatibility must still be treated as absent or conditional:

- `C_WaitForSlotEvent` -> unsupported
- `C_GetFunctionStatus` -> unsupported
- `C_CancelFunction` -> unsupported
- `C_SignRecoverInit` / `C_SignRecover` -> unsupported
- `C_VerifyRecoverInit` / `C_VerifyRecover` -> unsupported
- `C_DigestEncryptUpdate` -> unsupported
- `C_DecryptDigestUpdate` -> unsupported
- `C_SignEncryptUpdate` -> unsupported
- `C_DecryptVerifyUpdate` -> unsupported

This means the wrapper surface is broader than the Luna standard subset. That is acceptable, but Luna-specific docs should continue to describe these as **capability-gated or unavailable**, not as “supported because the wrapper has a method”.

### 2. Partition vs keyring differences

The public Luna compliance table reviewed here distinguishes Luna partitions and Luna keyrings for some functionality.

Most notably:

- `C_GetOperationState` -> supported on partitions, not on keyrings
- `C_SetOperationState` -> supported on partitions, not on keyrings

The current repo already uses a capability-gated mindset for operation-state validation, which fits Luna well.

### 3. Helper coverage is smaller than the full Luna mechanism catalog

The wrapper's first-class mechanism constants and parameter helpers are intentionally selective. The native marshalling layer has special parameter handling for a small standard set such as:

- ECDH derive
- AES-CTR
- AES-GCM
- AES-CCM
- RSA OAEP
- RSA PSS

Everything else depends on whether a Luna mechanism can be used with:

- no parameter
- a flat byte parameter blob
- or a vendor/native structure that would need new marshalling support

So the compatibility answer for many Luna-public mechanisms is:

- **numeric mechanism IDs are representable today**
- **simple parameter cases may work today**
- **structured vendor-specific parameter layouts may need wrapper work**

### 4. PKCS#11 v3 on Luna is not proven by the public docs reviewed here

The repo supports:

- `C_GetInterfaceList`
- `C_GetInterface`
- `C_LoginUser`
- `C_SessionCancel`
- `C_MessageEncrypt*`
- `C_MessageDecrypt*`
- `C_MessageSign*`
- `C_MessageVerify*`

But the public Luna standard compliance page reviewed for this audit is still centered on the classic function table up through `C_CancelFunction`, and the reviewed Luna sample documentation focuses on `C_GetFunctionList` plus `CA_GetFunctionList`.

So current status for Luna is:

- **wrapper support exists**
- **public Luna support was not confirmed in this audit**
- these paths should remain **capability-gated / unverified for Luna** until a Luna runtime exports and passes them

## Where compatibility is vendor-extension-only and currently missing

This is the biggest gap.

The public Luna extensions page shows a **large `CA_*` surface** (roughly 300 extension entry points in the reviewed public index). Examples span areas such as:

- cloning and cloning domain control
- HA control / secondary-slot orchestration
- container and keyring administration
- MofN and PED workflows
- STC / STM features
- policy and HSM administration
- BIP32-related extension helpers
- special wrap/control operations such as `CA_WrapKeyWithScheme`
- extension equivalents like `CA_WaitForSlotEvent` and `CA_SessionCancel`

Current repo status is clear:

- `Pkcs11NativeModule.Load(...)` resolves `C_GetFunctionList`
- it optionally resolves `C_GetInterfaceList` and `C_GetInterface`
- it does **not** resolve `CA_GetFunctionList`
- there is **no** `CA_*` interop structure or managed projection in the current codebase
- the admin panel has **no** Luna extension workflows
- the smoke/vendor docs validate only standard PKCS#11 flows

So any compatibility claim for Luna extension APIs would be inaccurate today.

## Admin/runtime/doc implications

### Core wrapper

Current core guidance for Luna should be:

- standard `C_*` compatibility is the supported path
- raw numeric mechanism/attribute values are available when needed
- Luna extension entry points are out of scope for the current wrapper

### Admin panel

Current admin guidance for Luna should be:

- **device profiles** can point at a Luna PKCS#11 library path
- **PKCS#11 Lab** is the best current UI for mechanism probing and raw attribute reads
- curated admin pages are intentionally standard-centric
- no Luna-specific UI exists for HA, container management, PED/MofN, STC/STM, or cloning

A small but relevant nuance: the admin detail views use a curated standard attribute list, while the lab can read arbitrary attribute types by numeric input. That makes the lab the safer current surface for Luna-specific inspection.

### Runtime validation

Current runtime guidance for Luna should be:

- use the existing vendor lane with explicit `PKCS11_*` environment variables
- treat missing mechanisms or unsupported calls as capability gates, not automatic wrapper defects
- do not read SoftHSM-only validation depth as proof of Luna extension coverage

### Documentation

Current documentation should point readers to this audit whenever “vendor compatibility” or “Luna support” comes up, so expectations stay precise.

## Practical bottom line

### Supported well today

- standard Luna PKCS#11 module/session/object/crypto/key-management flows
- explicit Luna library path usage through device profiles or `PKCS11_MODULE_PATH`
- generic mechanism/attribute probing through the admin lab
- standard vendor-lane smoke/regression work against a prepared Luna environment

### Supported conditionally / capability-gated

- operation-state on Luna partitions
- any mechanism that depends on actual Luna firmware/token policy/mechanism exposure
- wrapper methods whose corresponding standard Luna function is documented as unsupported
- any PKCS#11 v3 path until validated against a Luna runtime that actually exports it
- mechanisms that need structured parameters not currently marshalled by the wrapper

### Not supported today

- Luna `CA_*` extension APIs via `CA_GetFunctionList`
- Luna-specific HA/container/cloning/PED/MofN/STC/STM/policy-admin flows
- Luna extension replacements such as `CA_WaitForSlotEvent` or `CA_SessionCancel`
- any claim that the admin panel or runtime tooling currently covers Luna-only APIs directly

## Suggested follow-up work

If deeper Luna support becomes a product goal later, the clean next steps would be separate issues such as:

1. add optional `CA_GetFunctionList` loading and a scoped Luna extension interop layer (now designed in `docs/luna-vendor-extension-design.md`)
2. add named constants/helpers for the Luna-public mechanisms that are already reachable through standard `C_*` calls
3. add a Luna-specific vendor regression profile or sample env contract once a real Luna-backed CI/manual lane exists

## Conclusion

For issue #30, the compatibility result is:

- **standard Luna PKCS#11 compatibility:** broadly good with normal vendor/module capability caveats
- **Luna public mechanism breadth:** partially reachable today because the wrapper accepts raw numeric values, but helper coverage is selective
- **Luna vendor extension compatibility:** not implemented and should not be claimed

That is the accurate current boundary of the repository.
