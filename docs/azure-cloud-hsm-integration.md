# Azure Cloud HSM integration guide

See also:

- `docs/azure-cloud-hsm-compatibility-audit.md` for the conservative compatibility audit against Azure public documentation
- `docs/compatibility-matrix.md` for the repo-wide support summary and current limits
- `docs/vendor-regression.md` for why there is not yet a checked-in Azure Cloud HSM vendor-regression profile

## Purpose

This guide turns the Azure Cloud HSM research from issue #70 into a practical setup path for the current repository.

It is intentionally conservative:

- it shows the practical current path for the **wrapper** and **admin panel**
- it distinguishes **Azure Cloud HSM** from **Azure Managed HSM** and other adjacent Azure key-management surfaces
- it documents the Linux/Windows/client/setup/auth constraints that matter operationally
- it distinguishes what is **ready now**, what is **blocked by abstraction boundaries**, and what still needs a **real Azure Cloud HSM environment** to validate honestly

## Azure public references reviewed

The current guidance in this document is based primarily on:

- Azure Cloud HSM overview: <https://learn.microsoft.com/en-us/azure/cloud-hsm/overview>
- Azure Cloud HSM FAQ: <https://learn.microsoft.com/en-us/azure/cloud-hsm/faq>
- Azure Cloud HSM authentication: <https://learn.microsoft.com/en-us/azure/cloud-hsm/authentication>
- Azure Cloud HSM integration guides: <https://learn.microsoft.com/en-us/azure/cloud-hsm/integration-guides>
- Azure Cloud HSM PKCS#11 integration guide (PDF): <https://github.com/microsoft/MicrosoftAzureCloudHSM/blob/main/IntegrationGuides/Azure%20Cloud%20HSM%20PKCS11%20Integration%20Guide.pdf>
- Azure Cloud HSM network security: <https://learn.microsoft.com/en-us/azure/cloud-hsm/network-security>
- Azure Cloud HSM user management best practices: <https://learn.microsoft.com/en-us/azure/cloud-hsm/user-management>
- Azure Managed HSM overview: <https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview>
- Azure Dedicated HSM overview: <https://learn.microsoft.com/en-us/azure/dedicated-hsm/overview>

## What “Azure Cloud HSM support” means in this repo today

The key design fact is that **Azure Cloud HSM is the direct PKCS#11 fit in Azure for this repo**.

The practical support story here is:

### Supported well enough to use now

- explicit Azure Cloud HSM PKCS#11 module-path loading through `Pkcs11Module.Load(...)`
- standard module / slot / token / mechanism enumeration over Azure Cloud HSM's PKCS#11 library
- standard session open + `C_Login` flows using Azure Cloud HSM's documented `username:password` credential format
- standard object discovery / attribute reads and standard crypto workflows where the live module exposes them as documented
- admin-panel device registration through a built-in **Azure Cloud HSM / standard PKCS#11** vendor profile
- stronger repo documentation for the Azure runtime/config/auth boundary instead of leaving operators to infer it from generic PKCS#11 assumptions

### Important boundaries

- this repo does **not** provision Azure Cloud HSM resources, private endpoints, virtual-network plumbing, SSH access, or onboarding steps
- this repo does **not** manage Azure Cloud HSM's `azcloudhsm_client` service, `azcloudhsm_resource.cfg`, `azcloudhsm_application.cfg`, or partition owner certificate placement for you
- this repo does **not** manage Cloud HSM cryptography officer (CO) / cryptography user (CU) creation, password reset, node synchronization, or backup/restore workflows
- this repo does **not** provide a checked-in Azure Cloud HSM smoke or vendor-regression profile, because no live Azure Cloud HSM environment was available during issue #70
- this repo does **not** turn Azure Managed HSM into a PKCS#11 module path; Managed HSM is a different Azure Key Vault/API boundary

## Azure product boundary that matters here

### Azure Cloud HSM: the direct PKCS#11 fit

Azure's public docs position **Azure Cloud HSM** as a single-tenant, highly available HSM service intended for workloads that need direct HSM-style integration from Azure virtual machines and similar IaaS deployments.

For this repo, that matters because Azure Cloud HSM explicitly documents:

- PKCS#11 support
- host-local SDK/runtime installation
- host-local client/service configuration
- direct application login via `C_Login`

That matches the current `Pkcs11Wrapper` + admin-panel architecture well.

### Azure Managed HSM: a different abstraction boundary

Azure's public docs position **Azure Key Vault Managed HSM** differently:

- it is part of the Key Vault family
- it is integrated with Azure/Microsoft PaaS and SaaS customer-managed-key scenarios
- it is managed through Azure APIs/SDKs and Azure-native control planes

For this repo, that means:

- **Azure Managed HSM is not the practical direct PKCS#11 target described by issue #70**
- if a future repo issue wants Managed HSM support, that would be a **different abstraction layer** than today's standard PKCS#11 wrapper/admin boundary

### Azure Dedicated HSM: predecessor/migration context

Azure's current docs say **Azure Cloud HSM is the successor to Azure Dedicated HSM**.

That matters because it clarifies the migration story:

- customers who previously thought about Azure's older dedicated-HSM offering should now evaluate **Cloud HSM** for the direct-HSM path
- that is a better conceptual match for this repo than treating issue #70 as an Azure Key Vault / Managed HSM feature request

## Azure Cloud HSM model that matters for this repo

From the reviewed Azure public docs and Microsoft's PKCS#11 integration guide, the key integration facts are:

- Azure Cloud HSM is a **direct** host-local client/runtime story rather than an indirect adapter like Google's kmsp11
- Azure Cloud HSM is an **IaaS-oriented** service, not a generic Azure PaaS/SaaS key-store integration path
- Azure Cloud HSM access is expected through private networking and host-local SDK/client configuration
- the Azure Cloud HSM PKCS#11 library expects the host to have:
  - the Azure Cloud HSM SDK installed
  - a valid `azcloudhsm_resource.cfg`
  - a valid `azcloudhsm_application.cfg`
  - a copy of the partition owner certificate `PO.crt`
  - a running `azcloudhsm_client`
- PKCS#11 login uses `C_Login` with credentials in the form **`username:password`**
- Azure documents only **password-based authentication**; it does **not** support a PED-based auth flow
- Azure documents that `C_Initialize` should be called once and that each thread should use its own session
- Azure documents that the client can sign in/out all HSM sessions on the host together, so overlapping local tools/processes can interfere with each other if you are careless

## Prerequisites

Before pointing this repo at Azure Cloud HSM, make sure:

1. the host or container that runs the code already has the official Azure Cloud HSM SDK installed
2. the host already has network connectivity to the Azure Cloud HSM private endpoint / virtual-network path you intend to use
3. the host already has the correct `PO.crt` and `azcloudhsm_resource.cfg` material for the target cluster
4. `azcloudhsm_client` is already running on that same host/container
5. the process can resolve the exact PKCS#11 library path from the installed SDK
6. the process runtime has the required `azcloudhsm_application.cfg` file available where the Azure PKCS#11 client expects it
7. the intended CO/CU users already exist and are synchronized correctly across the Cloud HSM nodes
8. you understand that cluster/user/bootstrap work remains an Azure operational responsibility outside this repo

### Authentication expectations

Azure documents these key points for authentication:

- PKCS#11 clients authenticate with `C_Login`
- the PIN bytes should be passed in the form **`username:password`**
- Azure Cloud HSM supports **password-based authentication only**
- Azure Cloud HSM does **not** support a PIN entry device (PED)

Practical implication for this repo:

- the wrapper/admin panel can already pass arbitrary login bytes, so the credential shape fits the current API cleanly
- operators still need to manage the secret securely outside the app
- if local tools like `azcloudhsm_util` already hold an active sign-in on the same host, they can interfere with application usage because Azure documents shared client-session behavior on a host

## Linux and Windows setup expectations

### Runtime/library layout

The repo does not auto-discover Azure Cloud HSM for you. You must provide the exact PKCS#11 module path that the current host can load.

Microsoft's public PKCS#11 guide shows examples such as:

- Linux: `/opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so`
- Windows: `C:\Program Files\Microsoft Azure Cloud HSM Client SDK\libs\pkcs11\azcloudhsm_pkcs11.dll`

The same guide also documents that the supporting runtime/config files matter, not just the PKCS#11 DLL/SO itself.

### Published platform expectations

Azure's reviewed public docs publish both **Linux** and **Windows Server** support for the SDK/client path.

The exact supported OS-version list varies slightly across the reviewed Azure pages and integration-guide snapshots, so the conservative guidance for this repo is:

- treat **Linux** and **Windows Server** as supported Azure Cloud HSM client platforms
- verify the exact SDK release + OS combination against the Azure docs/release you are actually deploying
- if the admin panel runs in a container, the Azure SDK, config files, certificates, and daemon/runtime dependencies must exist **inside that container**, not only on the host

### Client/runtime files that matter operationally

Azure's PKCS#11 guide calls out several runtime pieces explicitly:

- `azcloudhsm_client`
- `azcloudhsm_resource.cfg`
- `azcloudhsm_application.cfg`
- `PO.crt`

The guide also states that `azcloudhsm_client` should normally run as a service in production.

Practical implication for this repo:

- the wrapper/admin panel should be treated as a **consumer** of an already-working Azure client runtime
- if those files or the client daemon are missing, the app should be expected to fail to initialize/login rather than magically bootstrap Azure for the operator

## Point the core wrapper at Azure Cloud HSM

The simplest current integration path is the standard module load plus Azure's documented client/runtime prerequisites on the host:

```csharp
using System.Text;
using Pkcs11Wrapper;

using Pkcs11Module module = Pkcs11Module.Load("/opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so");
module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

Pkcs11SlotId slotId = module.GetSlotIds(tokenPresentOnly: true)[0];
using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes("cu1:SecretPassword"));
```

Practical guidance:

- use the exact PKCS#11 library path from the installed Azure SDK
- expect `C_OpenSession` + `C_Login` to work only after the Azure runtime/config/daemon prerequisites are already correct
- prefer real slot/mechanism inspection over assumptions, especially before relying on advanced object-management or mechanism-specific flows
- initialize once and use per-thread sessions, following Azure's multithreading guidance
- add retry logic around real operations; Azure documents that maintenance or node replacement can temporarily affect cluster availability

## Point the admin panel at Azure Cloud HSM

The current admin path is:

1. run `src/Pkcs11Wrapper.Admin.Web` on a machine/container that already has the Azure Cloud HSM SDK/runtime working
2. make sure the same runtime already has the required Azure config/certificate files plus a running `azcloudhsm_client`
3. open the **Devices** page
4. create or edit a device profile with:
   - **Name**: your operational Azure Cloud HSM profile label
   - **PKCS#11 Module Path**: the exact Azure PKCS#11 library path on that host
   - **Default Token Label**: optional, depending on how your Azure environment exposes slots/tokens
   - **Vendor profile**: **Azure Cloud HSM / standard PKCS#11**
   - **Notes**: optional resource/private-endpoint/client-version/operator breadcrumbs
5. use the built-in **Test** action before relying on the profile

### What is improved in this slice

The admin panel now has a built-in Azure-specific readiness improvement:

- a built-in **Azure Cloud HSM / standard PKCS#11** vendor profile that keeps the most important Azure-specific guidance visible to operators

That makes the Azure path materially clearer in these admin surfaces:

- **Devices** connection testing
- **Slots / Keys** browsing and capability inspection
- **Sessions** / **PKCS#11 Lab** diagnostics that stay inside standard PKCS#11 flows
- operator-visible reminders that Azure Cloud HSM is a direct SDK/client runtime, while Managed HSM remains a different Azure service boundary

### What not to expect from the admin panel today

Do **not** expect the admin panel to:

- provision an Azure Cloud HSM resource
- create private endpoints or Azure virtual-network plumbing
- SSH into the cluster or run Azure onboarding steps for you
- create/synchronize CO/CU users across nodes
- manage `azcloudhsm_client` as a service
- author or distribute `azcloudhsm_resource.cfg`, `azcloudhsm_application.cfg`, or `PO.crt`
- turn Azure Managed HSM or broader Azure customer-managed-key scenarios into this repo's PKCS#11 module path

## Compatibility notes that matter for wrapper/admin usage

### Azure's documented PKCS#11 surface is broad enough for a strong first support slice

Microsoft's public PKCS#11 integration guide documents support for standard operations including:

- lifecycle / info: `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`
- slot/token/mechanism enumeration
- sessions/login/logout
- object-management functions such as `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_SetAttributeValue`, and `C_FindObjects*`
- crypto flows including digest, sign/verify, sign-recover / verify-recover, encrypt/decrypt, and multipart variants
- random + key-management functions such as `C_SeedRandom`, `C_GenerateRandom`, `C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, and `C_DeriveKey`
- legacy parallel-function calls `C_GetFunctionStatus` and `C_CancelFunction`

That means Azure Cloud HSM is a **direct** and relatively broad standard-PKCS#11 fit for this repo compared with several other cloud-vendor targets.

### Certificate-object support is explicitly documented

Azure's PKCS#11 guide explicitly documents certificate storage support and ties `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_SetAttributeValue`, and `C_FindObjects*` to certificate-object workflows.

Practical implication:

- the broad standard object-management story looks promising
- but issue #70 should still avoid over-claiming specific live key-object behaviors that were not validated against a real Azure cluster

### PKCS#11 v3-only paths remain unclaimed

The reviewed Azure PKCS#11 guide was sufficient to document a broad standard PKCS#11 fit, but issue #70 did **not** use Azure public docs to prove:

- `C_GetInterface*`
- `C_Message*`
- `C_LoginUser`
- `C_SessionCancel`

So the correct current stance is:

- wrapper support exists generically
- Azure Cloud HSM support for those PKCS#11 v3-only paths remains **unclaimed/unvalidated** in the current issue slice

## What can vs cannot be validated locally without real Azure access

### What can be validated locally in issue #70

Without real Azure Cloud HSM access, this issue could validate:

- documentation correctness against reviewed Azure public docs
- compile/build correctness of the admin vendor-profile wiring
- unit-test coverage of the Azure vendor-profile catalog behavior
- repo-level clarity about the Azure Cloud HSM vs Managed HSM boundary

### What cannot be validated honestly without real Azure access

Without a live Azure Cloud HSM environment, this issue could **not** honestly validate:

- real Azure private-endpoint / virtual-network connectivity
- real SDK installation-path behavior on target Linux/Windows hosts
- real `azcloudhsm_client` service behavior under the admin panel or wrapper
- real `azcloudhsm_application.cfg` placement/lookup behavior for this app on every deployment shape
- real `C_Login` success/failure paths against a live CU user
- real slot/token/object exposure for a live cluster
- real create/copy/edit/destroy semantics for key objects under a live Azure policy
- real sign/verify/encrypt/decrypt/digest/wrap/unwrap/derive behavior against live HSM-backed keys
- real multi-process/session-sharing interference on a shared host
- real admin-panel end-to-end behavior against Azure Cloud HSM

## Practical conclusion

The current repo should describe Azure Cloud HSM support as:

- **direct PKCS#11 support through Azure's Cloud HSM SDK/library**
- **a materially better fit for the current wrapper/admin boundary than Azure Managed HSM**
- **admin-panel-ready enough for device registration, inspection, diagnostics, and honest operator guidance**
- **not yet live-validated without a real Azure Cloud HSM environment**
- **not a blanket claim that the repo now manages Azure onboarding/control-plane tasks**

That is the honest and useful first support slice for issue #70.
