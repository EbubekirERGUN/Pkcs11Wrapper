# Azure Cloud HSM compatibility audit

See also:

- `docs/azure-cloud-hsm-integration.md` for the practical wrapper/admin-panel setup path
- `docs/compatibility-matrix.md` for the repo-wide support summary
- `docs/vendor-regression.md` for the current vendor-lane boundary

## Scope

This document records the research for issue #70 and answers a narrow question:

> How well does Azure Cloud HSM fit the current `Pkcs11Wrapper` + admin-panel architecture?

The short answer is:

- **better than the indirect adapter-style cloud PKCS#11 story represented by Google kmsp11**
- **closer to IBM HPCS and OCI Dedicated KMS in that Azure documents a direct host-local PKCS#11 client path**
- **still bounded by real Azure runtime/config/network requirements that cannot be faked from docs alone**

The practical fit for the current repo is:

- **direct PKCS#11** through Azure Cloud HSM's SDK/client library
- **not** an Azure Managed HSM feature, because Managed HSM is a different Azure Key Vault/API abstraction boundary
- **not** a reason to pretend that Azure onboarding, networking, SSH, user sync, or backup/restore are already repo-managed features

## Azure public references reviewed

The research for this issue was based on Azure public material that, at the time of review, stated the following:

- Azure Cloud HSM overview: <https://learn.microsoft.com/en-us/azure/cloud-hsm/overview>
  - documents Cloud HSM as a single-tenant, highly available service with PKCS#11 support
  - states Cloud HSM is best suited for IaaS migration scenarios and is **not** the right fit for Azure PaaS/SaaS customer-managed-key scenarios
- Azure Cloud HSM FAQ: <https://learn.microsoft.com/en-us/azure/cloud-hsm/faq>
  - documents SDK availability, supported OS families, SSH/SDK management expectations, and direct-vs-Managed-HSM selection guidance
- Azure Cloud HSM authentication: <https://learn.microsoft.com/en-us/azure/cloud-hsm/authentication>
  - documents password-only auth, PKCS#11 `C_Login` with `username:password`, thread/session guidance, and shared host-side client-session behavior
- Azure Cloud HSM integration guides: <https://learn.microsoft.com/en-us/azure/cloud-hsm/integration-guides>
  - links the public PDF integration guides, including the PKCS#11 guide used below
- Azure Cloud HSM PKCS#11 integration guide (PDF): <https://github.com/microsoft/MicrosoftAzureCloudHSM/blob/main/IntegrationGuides/Azure%20Cloud%20HSM%20PKCS11%20Integration%20Guide.pdf>
  - documents SDK install/layout, module paths, `azcloudhsm_client`, `azcloudhsm_resource.cfg`, `azcloudhsm_application.cfg`, `PO.crt`, example `C_OpenSession`/`C_Login`, and a broad supported-PKCS#11-function table
- Azure Cloud HSM network security: <https://learn.microsoft.com/en-us/azure/cloud-hsm/network-security>
  - documents private-endpoint/private-link expectations
- Azure Cloud HSM user management best practices: <https://learn.microsoft.com/en-us/azure/cloud-hsm/user-management>
  - documents CO/CU/user-sync/password/partition-owner-certificate operational expectations
- Azure Managed HSM overview: <https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview>
  - documents Managed HSM as a Key Vault-family service integrated with Azure/Microsoft cloud-service encryption scenarios
- Azure Dedicated HSM overview: <https://learn.microsoft.com/en-us/azure/dedicated-hsm/overview>
  - documents that Azure Cloud HSM is the successor to Azure Dedicated HSM

## Repository areas reviewed

- `src/Pkcs11Wrapper*`
- `src/Pkcs11Wrapper.Admin.*`
- `tests/*`
- existing cloud-vendor docs for AWS, Google, IBM, and OCI

## Executive summary

### 1. Azure Cloud HSM is a real direct PKCS#11 fit for this repo

Azure Cloud HSM publishes a host-local SDK and a documented PKCS#11 library path.

That matches the repo's current architecture well:

- explicit module path
- standard `C_*` entry-point usage
- standard slot/session/object/mechanism workflows
- generic admin-panel diagnostics and device-profile guidance

This is **not** the same kind of abstraction mismatch as Google kmsp11, where the PKCS#11 face is clearly an adapter over another cloud-control plane.

### 2. Azure Managed HSM is a different product boundary and should stay out of current PKCS#11 claims

Azure's own docs make the distinction clear:

- **Cloud HSM** is the direct, IaaS-oriented HSM path
- **Managed HSM** is the Key Vault-family service used for Azure/Microsoft service integrations and Azure-native key-management scenarios

For this repo today:

- **Cloud HSM** is the relevant fit
- **Managed HSM** is out of scope for the current standard-PKCS#11 wrapper/admin architecture

### 3. Azure's published PKCS#11 surface is broad enough that the generic admin panel is a plausible fit

The reviewed Azure PKCS#11 guide publicly documents support for many standard functions that matter to the repo, including:

- `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`
- slot/token/mechanism enumeration
- `C_OpenSession`, `C_Login`, `C_Logout`, `C_CloseSession`, `C_CloseAllSessions`
- `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_SetAttributeValue`, `C_FindObjects*`
- `C_Encrypt*`, `C_Decrypt*`, `C_Digest*`, `C_Sign*`, `C_Verify*`, `C_SignRecover*`, `C_VerifyRecover*`
- `C_SeedRandom`, `C_GenerateRandom`, `C_GetFunctionStatus`, `C_CancelFunction`
- `C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`

That is materially broader than several other cloud-vendor PKCS#11 stories already documented in this repo.

### 4. Azure's direct path still depends on a real host-runtime contract outside this repo

Azure Cloud HSM is not just a DLL/SO drop.

The reviewed docs describe an operational contract that includes:

- private networking / private endpoint reachability
- Azure SDK installation
- `azcloudhsm_client`
- `azcloudhsm_resource.cfg`
- `azcloudhsm_application.cfg`
- `PO.crt`
- properly created/synchronized Cloud HSM users

That fits the repo **operationally**, but it is a host/runtime concern, not something the wrapper/admin panel currently provisions for the user.

### 5. Honest end-to-end validation still requires a real Azure Cloud HSM environment

The repo can now document Azure Cloud HSM well and improve admin-panel readiness without pretending it validated:

- real private-network connectivity
- real `azcloudhsm_client` behavior
- real CU login behavior
- real object/mechanism exposure
- real key-management semantics or policy behavior
- real Linux/Windows deployment quirks on a live Azure target

So the correct first slice is **docs + admin guidance + tests**, not a fake live-validation story.

## Compatibility assessment

## Standard wrapper fit

| Area | Current fit | Notes |
| --- | --- | --- |
| Module loading via explicit library path | Good fit | Azure publishes a host-local PKCS#11 library that the wrapper can load directly. |
| Standard `C_*` entry-point usage | Good fit | Azure publishes a broad PKCS#11 function table rather than an adapter-only subset. |
| Slot / token / mechanism inspection | Good fit | Azure documents standard slot/token/mechanism APIs. |
| Session + login/logout flows | Good fit | Azure documents `C_OpenSession`, `C_Login`, `C_Logout`, and the `username:password` credential shape. |
| Object discovery / reads | Good fit | Standard `C_FindObjects*` + `C_GetAttributeValue` are documented. |
| Object create/copy/edit/destroy | Partial but promising | Azure documents these functions and explicitly documents certificate-object support. Broader live key-object semantics still require real Azure validation. |
| Single-part and multipart crypto flows | Good fit on paper | Azure documents broad encrypt/decrypt/digest/sign/verify coverage. Live mechanism/policy/runtime proof is still required. |
| Random + key generation / wrap / unwrap / derive | Good fit on paper | Azure documents these standard functions, which lines up well with the repo's generic wrapper/admin capabilities. |
| Legacy parallel-function calls | Capability-gated but documented | Azure documents `C_GetFunctionStatus` and `C_CancelFunction`; the repo already treats these as capability-sensitive. |
| Provisioning/admin token functions (`C_InitToken`, `C_InitPIN`, `C_SetPIN`) | Unclaimed / unvalidated | The reviewed Azure PKCS#11 guide for issue #70 did not justify broad claims for these functions. |
| Operation-state flows (`C_GetOperationState`, `C_SetOperationState`) | Unclaimed / unvalidated | The reviewed Azure PKCS#11 guide for issue #70 did not justify these claims. |
| `C_WaitForSlotEvent` | Unclaimed / unvalidated | The reviewed Azure PKCS#11 guide for issue #70 did not justify this claim. |
| PKCS#11 v3-only interfaces/messages | Unclaimed / unvalidated | No current Azure public documentation reviewed for this issue was used to justify `C_GetInterface*`, `C_Message*`, `C_LoginUser`, or `C_SessionCancel` claims. |

## Azure-specific operational contract that matters

### Client/config model

Azure's direct PKCS#11 path requires more than a shared library:

- the Azure Cloud HSM SDK
- the PKCS#11 library path itself
- `azcloudhsm_client`
- `azcloudhsm_resource.cfg`
- `azcloudhsm_application.cfg`
- `PO.crt`
- private-network connectivity to the Cloud HSM cluster

That means the current repo should describe Azure like this:

- **direct PKCS#11 is the right abstraction boundary**
- but the repo consumes a **prepared Azure runtime** rather than creating it

### User/auth model

Azure's reviewed public docs describe:

- password-based authentication only
- `C_Login` credentials in the form `username:password`
- CU/CO-style operational roles outside the app
- customer-managed user synchronization across the Cloud HSM nodes

Practical implications:

- the wrapper/admin API can carry the login bytes cleanly
- Azure credential/bootstrap/user-management remains an operator concern
- user-sync failures across nodes are an Azure operational risk, not a wrapper feature

### Shared host-side client sessions

Azure's authentication docs explicitly warn that the host-side client can sign in/out all HSM sessions whenever one application signs in/out, and that a second application can fail if another Azure tool already holds the active session context.

That matters for this repo because it means:

- multi-process behavior should be treated carefully on a shared host
- login/session surprises are not necessarily wrapper bugs
- operators should avoid mixing ad-hoc Azure CLI/util sessions with app/admin usage carelessly on the same machine

### Networking / IaaS boundary

Azure's public docs say Cloud HSM is an **IaaS-only** fit and is **not** the right choice for Azure/Microsoft cloud-service customer-managed-key scenarios.

That lines up well with the repo boundary:

- this repo expects a host-local PKCS#11 module path
- this repo does **not** try to become an Azure service-encryption control plane
- if the real requirement is Azure-native cloud-service encryption, the correct Azure boundary is typically **Managed HSM**, not this repo's PKCS#11 path

## What already lines up well with the current repo

The following existing repo design choices age well for Azure Cloud HSM:

- explicit module-path loading instead of hidden vendor discovery
- strong standard `C_*` surface coverage in the wrapper
- admin-panel emphasis on live device testing, slot inspection, key browsing, and operator-visible boundaries
- vendor-profile guidance in the admin panel for environment/setup caveats
- willingness to keep cloud-vendor claims conservative until live validation exists

In other words, Azure Cloud HSM is a case where the current repo architecture is already reasonably shaped for the direct PKCS#11 path.

## What does not fit the current repo boundary

### Azure Managed HSM / Key Vault APIs

Managed HSM is a real Azure HSM product, but it is **not** the same thing as loading a host-local PKCS#11 module.

Supporting Managed HSM properly would likely require:

- a separate Azure API/client abstraction
- Azure identity/auth flows that are different from `C_Login`
- a different test story
- separate admin UX language

So issue #70 should not be framed as "support all Azure HSM products".

### Azure onboarding/control-plane work

The current admin panel should not imply support for:

- resource provisioning
- private endpoint/network creation
- SSH-driven setup
- CO/CU creation or repair
- partition owner certificate lifecycle operations
- backup/restore orchestration

Those are Azure operational paths, not current PKCS#11 wrapper/admin features.

## What can vs cannot be validated locally without real Azure access

### What can be validated locally in issue #70

Without real Azure access, this issue could validate:

- documentation correctness against reviewed Azure public docs
- compile/build correctness of the admin vendor-profile additions
- unit-test coverage of Azure vendor-profile catalog behavior
- the direct-vs-Managed-HSM architectural conclusion

### What cannot be validated honestly without real Azure access

Without a live Azure Cloud HSM environment, this issue could **not** honestly validate:

- actual Azure private-endpoint routing and host reachability
- actual SDK installation/runtime behavior on deployment targets
- real `azcloudhsm_client` lifecycle behavior
- real `azcloudhsm_application.cfg` lookup behavior for the admin app in all deployment shapes
- real CU login behavior, session concurrency, or host-sharing edge cases
- real slot/token/mechanism exposure
- real object-management behavior for keys/certificates under live policy
- real sign/verify/encrypt/decrypt/digest/wrap/unwrap/derive success against live keys
- real end-to-end admin-panel behavior against Azure hardware

## Practical conclusion

The current repo should describe Azure Cloud HSM support as:

- **a strong direct-PKCS#11 candidate for the current wrapper/admin boundary**
- **materially more aligned with this repo than Azure Managed HSM**
- **admin-panel-ready enough for vendor-aware device registration, inspection, and diagnostics**
- **not yet live-validated without a real Azure Cloud HSM environment**
- **not a claim that the repo now automates Azure onboarding/control-plane operations**

That is the honest and useful first support slice for issue #70.
