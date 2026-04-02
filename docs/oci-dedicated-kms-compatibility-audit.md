# OCI Dedicated KMS PKCS#11 compatibility audit

See also:

- `docs/oci-dedicated-kms-integration.md` for the practical wrapper/admin-panel setup path
- `docs/compatibility-matrix.md` for the repo-wide support summary
- `docs/vendor-regression.md` for the current vendor-lane boundary

## Scope

This document audits the **Oracle Cloud Infrastructure HSM / Key Management product mapping** and the **publicly documented OCI Dedicated KMS PKCS#11 fit** against the current `Pkcs11Wrapper` repository.

It is intentionally conservative:

- it distinguishes **OCI Dedicated KMS direct PKCS#11 support** from **OCI Vault / Key Management API surfaces** and other Oracle client surfaces
- it separates **already good repo alignment** from **real-runtime-only validation** and **different abstraction-boundary cases**
- it does **not** claim support that requires a real OCI environment when no live OCI HSM access was available during issue #68

## Oracle public references reviewed

- Dedicated KMS overview: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dedicated_kms.htm>
- Dedicated KMS getting started: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dedicated_kms_getting_started.htm>
- PKCS#11 library overview: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dedicated_kms_pkcs_library.htm>
- PKCS#11 install path / package expectations: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dedicated_kms_installation_pkcs_11.htm>
- PKCS#11 config path: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dedicated_kms_configuring_pkcs_11.htm>
- PKCS#11 authentication model: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dedicated_kms_pkcs_authentication.htm>
- client OS support: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dkms_installation_supported_system.htm>
- client parameter and certificate/daemon expectations: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dkms_configure_client_component_parameters.htm>
- Linux client installation flow: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dkms_linux_support.htm>
- client daemon configuration/start: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dedicated_kms_installation_configure_daemon.htm> and <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Reference/reference_dedicated_kms_installation_start_daemon.htm>
- Windows client / CNG-KSP path: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dkms_windows_CLI_download_install.htm> and <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dkms_windows_cng_ksp.htm>
- client changelog/download packaging: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dkms_downloads.htm>
- broader Vault / Key Management overview for product-boundary comparison: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm>
- public encrypt/decrypt mechanism page reviewed during this issue: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dedicated_kms_pkcs_encrypt_decrypt.htm>
- public sign/verify mechanism page reviewed during this issue: <https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/dedicated_kms_pkcs_sign_verify.htm>

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

The current repo is in a **good position for OCI Dedicated KMS as a direct Linux PKCS#11 integration**, but the issue only becomes clean once Oracle’s product boundary is stated explicitly.

The most important compatibility conclusions are:

1. **The practical direct-PKCS#11 target is OCI Dedicated KMS, not generic OCI Vault.**
   - Oracle’s Dedicated KMS docs explicitly describe a PKCS#11 v2.40 library and direct HSM interaction without OCI APIs.
   - Oracle’s broader Vault / Key Management docs describe an OCI service/API resource model instead.
   - So repo support should be described as **OCI Dedicated KMS direct PKCS#11 support**, not as blanket OCI Vault support.

2. **The wrapper is already structurally compatible with the documented Dedicated KMS PKCS#11 shape.**
   - Explicit module loading, standard session/login flows, object discovery, and generic standard mechanisms line up with the Oracle docs reviewed here.
   - No Oracle-specific wrapper assembly is required for the first useful slice.

3. **The direct current repo fit is Linux-first.**
   - Oracle’s reviewed docs publish Linux PKCS#11 packages and installation paths under `/opt/oci/hsm`.
   - The reviewed Windows docs describe client service + CNG/KSP flows instead of a documented Windows PKCS#11 DLL path for the current repo boundary.

4. **Admin-panel work needed operator clarity more than runtime shims.**
   - The most valuable first repo change is to keep Oracle product/setup boundaries visible in the device profile UX.
   - That is more honest than pretending the admin panel can provision OCI or consume Windows CNG/KSP.

5. **A real OCI environment is still required for honest end-to-end validation.**
   - This issue improves documentation and admin readiness.
   - It does not pretend that compile-time work equals live OCI HSM proof.

## Compatibility assessment

| OCI area | Oracle public documentation | Current repo status | Assessment |
| --- | --- | --- | --- |
| OCI Dedicated KMS direct PKCS#11 boundary | Explicitly documented by Oracle | Wrapper/admin already consume standard PKCS#11 modules | **Correct direct fit** |
| OCI Vault / Key Management service boundary | Documented as OCI vault/key service resources and OCI-native key-management concepts | Repo is a PKCS#11 wrapper/admin surface, not an OCI SDK client | **Different abstraction boundary** |
| OCI External KMS / HYOK style boundary | Documented as external-key-management model in OCI KMS overview | Repo has no OCI external-KMS API integration layer | **Different abstraction boundary** |
| Core module lifecycle (`C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`) | Oracle documents PKCS#11 v2.40 library availability | Fully wrapped in core | **Already good, pending live runtime** |
| Slot / token / mechanism enumeration | Inherent to the documented PKCS#11 library model | Fully wrapped and used by admin tooling | **Already good, pending live runtime** |
| `C_Login` credential format | Oracle explicitly documents `username:password` CU login | Wrapper/admin can already pass arbitrary login bytes; docs now capture Oracle semantics | **Already good once documented** |
| Standard encrypt/decrypt using documented mechanisms (`CKM_AES_*`, `CKM_RSA_PKCS`, `CKM_RSA_PKCS_OAEP`) | Explicitly documented | Wrapped in core; lab/admin can drive generic flows | **Already good for documented mechanism families, pending live runtime** |
| Standard sign/verify using documented RSA/ECDSA/HMAC mechanisms | Explicitly documented | Wrapped in core; lab/admin can drive generic flows | **Already good for documented mechanism families, pending live runtime** |
| Generic object discovery / detail / attribute reads | Fits the documented PKCS#11 usage model, but reviewed Oracle docs do not publish a full supported-API matrix | Wrapped heavily in core/admin | **Reasonable fit, but not exhaustively proven from docs alone** |
| Generic create/import/copy/edit/destroy flows | Oracle docs reviewed for this issue do not publish a complete function-by-function matrix that proves these individually | Wrapper/admin support exists generically | **Treat as plausible but real-runtime-dependent** |
| PKCS#11 v3 interface discovery (`C_GetInterface*`) | Oracle docs reviewed here describe PKCS#11 v2.40 | Wrapper supports it generically | **Unclaimed for OCI** |
| PKCS#11 v3 message APIs (`C_Message*`) | Oracle docs reviewed here describe PKCS#11 v2.40 | Wrapper supports them generically | **Unclaimed for OCI** |
| `C_LoginUser` / `C_SessionCancel` | Not documented in reviewed OCI v2.40 material | Wrapper supports them generically | **Unclaimed for OCI** |
| Linux client runtime requirements | Explicitly documented (`oci-hsm-client`, `oci-hsm-pkcs11`, `/opt/oci/hsm`, `client_daemon`) | Repo assumes host-local runtime already exists | **Already aligned operationally** |
| Windows support path | Oracle documents Windows client + CNG/KSP | Repo consumes PKCS#11 modules, not CNG/KSP | **Outside current repo boundary** |

## Where compatibility is already good

### 1. Standard `C_*` wrapper architecture matches the Dedicated KMS direction

The repo already exposes the standard Cryptoki surface that Oracle’s Dedicated KMS PKCS#11 docs imply.

That means the first useful OCI slice does **not** require a new Oracle-specific wrapper package just to get started.

### 2. Explicit module-path loading is the right operational model

`Pkcs11Wrapper` already expects an explicit module path.

That matches OCI Dedicated KMS well because Oracle expects a host-local client runtime with host-local config, certs, and daemon processes before the module is used.

### 3. The admin panel can already act as a consumer/diagnostics surface

Once the OCI runtime is installed and the daemon is working, the admin panel is already a reasonable fit for:

- device registration
- connection testing
- slot/mechanism inspection
- key/object discovery
- read-oriented diagnostics in the PKCS#11 Lab

## Where compatibility is capability-gated or future work

### 1. OCI support should not be described as blanket OCI Vault support

This is the most important conceptual boundary.

The repo should talk about Oracle support as:

- **direct PKCS#11 through OCI Dedicated KMS**

not as:

- generic **OCI Vault support**

because those are different operational and API surfaces.

### 2. Windows Oracle support is not the same as Windows PKCS#11 support here

Oracle clearly documents Windows client + CNG/KSP usage.

That is real Oracle support, but it is **not the abstraction boundary this repo currently implements**. So the current repo should not imply that Oracle’s Windows docs automatically equal a Windows `Pkcs11Wrapper` device-profile path.

### 3. Broad object-management claims should stay conservative

The reviewed Oracle docs confirm the overall PKCS#11 direction plus authentication and specific crypto mechanisms, but they do **not** provide the same kind of exhaustive function table that some other vendors publish.

So the repo should avoid over-claiming support for every object-management/admin flow from docs alone.

### 4. PKCS#11 v3 should remain unclaimed for OCI

The reviewed OCI material explicitly talks about a **PKCS#11 v2.40** library.

Therefore the repo should not infer OCI support for:

- `C_GetInterface*`
- `C_Message*`
- `C_LoginUser`
- `C_SessionCancel`

just because the wrapper can model them generically.

## OCI-specific operational constraints that affect repo design

### 1. The client daemon is part of the real runtime contract

Oracle’s Linux client flow depends on a configured and running `client_daemon`.

Repo implication:

- module-path correctness alone is insufficient
- admin-panel connection failures may be client-daemon/bootstrap problems rather than wrapper bugs

### 2. Certificate/bootstrap material is outside the repo boundary

Oracle’s client config depends on artifacts such as:

- `cert-c`
- `pkey-c`
- `partitionOwnerCert.pem`

Repo implication:

- the repo should document these requirements clearly
- it should not pretend to generate or manage them for the user

### 3. Key visibility is CU-scoped and replica-sensitive

Oracle documents that the app runs as a CU and can manage only keys it owns or shares, and that customers are responsible for synchronizing users/keys across replicas.

Repo implication:

- object inventory is legitimately environment/user dependent
- “it works in one partition/replica but not another” can be an OCI prep issue rather than a wrapper bug

## What could be validated locally in issue #68

Without a real OCI environment, this issue could validate:

- Oracle product mapping and abstraction-boundary analysis
- documentation correctness against Oracle public docs
- compile/build correctness of the new Oracle vendor-profile wiring
- unit-test coverage of the Oracle vendor-profile catalog entry

## What could not be validated honestly in issue #68

Without a live OCI Dedicated KMS environment, this issue could **not** honestly validate:

- actual client RPM installation behavior
- actual module-path resolution on a prepared Oracle Linux host
- daemon connectivity to a real HSM cluster
- CU login and key-ownership/sharing behavior
- real slot/token/mechanism exposure
- create/import/copy/edit/destroy behavior against real OCI policy/runtime
- end-to-end admin-panel behavior against OCI Dedicated KMS
- real smoke or vendor-regression success against OCI Dedicated KMS

## Practical conclusion

The current repo should describe Oracle cloud HSM support as:

- **direct PKCS#11 support through OCI Dedicated KMS on the documented Linux client path**
- **not a blanket claim that OCI Vault/private-vault service flows are direct PKCS#11 targets**
- **not a blanket Windows claim, because Oracle’s reviewed Windows docs are CNG/KSP rather than the current repo boundary**
- **admin-panel-ready enough for device registration, inspection, and operator guidance**
- **not yet live-validated without real OCI access**

That is the honest and useful first support slice for issue #68.
