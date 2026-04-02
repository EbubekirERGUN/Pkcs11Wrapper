# AWS CloudHSM integration guide

See also:

- `docs/cloudhsm-compatibility-audit.md` for the conservative compatibility audit against AWS public documentation
- `docs/compatibility-matrix.md` for the repo-wide support summary and current limits
- `docs/vendor-regression.md` for why there is not yet a checked-in CloudHSM vendor-regression profile

## Purpose

This guide turns the CloudHSM research from issue #66 into a practical setup path for the current repository.

It is intentionally conservative:

- it describes how to use **standard PKCS#11 `C_*` flows** with **AWS CloudHSM Client SDK 5**
- it shows the practical current path for the **wrapper** and **admin panel**
- it documents the Linux/Windows bootstrap/auth/session constraints that matter operationally
- it distinguishes what is **ready now**, what is **capability-gated**, and what still needs a **real CloudHSM environment** to validate honestly

## What “AWS CloudHSM support” means in this repo today

The current repo is a reasonable fit for **standard AWS CloudHSM PKCS#11 usage** when the scenario stays inside the subset that AWS documents for Client SDK 5.

That means the practical support story is:

### Supported well enough to use now

- explicit AWS CloudHSM PKCS#11 module-path loading through `Pkcs11Module.Load(...)`
- standard module / slot / token / mechanism enumeration
- user login via standard `C_Login`
- standard object search and attribute reads through `C_FindObjects*` / `C_GetAttributeValue`
- standard create / destroy / generate / wrap / unwrap flows that AWS documents for Client SDK 5
- admin-panel device profiles via the new **AWS CloudHSM / standard PKCS#11** vendor profile
- admin-panel browse/lab compatibility improvement for CloudHSM’s **read-write-session-only** behavior

### Important boundaries

- this repo does **not** implement AWS control-plane operations such as cluster bootstrap, cluster lifecycle, VPC/network setup, trust-anchor management, or CloudHSM CLI/CMU user administration
- this repo does **not** currently provide a checked-in CloudHSM smoke or vendor-regression profile, because some existing validation flows assume semantics that AWS SDK 5 does not expose
- vendor-defined CloudHSM mechanisms/types are **not** currently represented by first-class named constants throughout the wrapper, even though the core numeric types can still carry raw values

## AWS CloudHSM Client SDK 5 model that matters here

From AWS public documentation, the key integration facts are:

- the PKCS#11 library is documented as **PKCS#11 v2.40-compliant**
- the runtime lives under:
  - **Linux**: `/opt/cloudhsm`
  - **Windows binaries**: `C:\Program Files\Amazon\CloudHSM`
  - **Windows config/logs**: `C:\ProgramData\Amazon\CloudHSM`
- the client must be bootstrapped to a cluster using the AWS configure tool and the cluster/customer CA certificate
- the PKCS#11 login PIN format is **`<crypto-user-name>:<password>`**
- **read-only sessions are not supported in SDK 5**; `C_OpenSession` without `CKF_RW_SESSION` is documented to fail with `CKR_FUNCTION_FAILED`
- key handles are **session-specific** in SDK 5 and should be reacquired per run/session
- multi-slot mode in SDK 5 represents **multiple cluster connections** from one application, not just arbitrary local token fan-out

## Prerequisites

Before pointing this repo at CloudHSM, make sure:

1. the host or container that runs the code already has **AWS CloudHSM Client SDK 5** installed
2. the host has the required **customer/issuing certificate** in place
3. the client has already been **bootstrapped/configured** to the target cluster
4. the process can resolve the intended PKCS#11 module path from that installed SDK
5. you have a valid **crypto user (CU)** and password for application login
6. if you plan to use object-management flows, you understand the current object ownership/sharing model for that CU

## Linux and Windows setup expectations

### Install/runtime layout

The repo does not auto-discover CloudHSM for you. You must provide the exact PKCS#11 module path that the current host can load.

Practical guidance:

- on Linux, expect the relevant files under `/opt/cloudhsm`
- on Windows, expect binaries under `C:\Program Files\Amazon\CloudHSM`
- keep the **exact** library path in app configuration / device profile instead of hard-coding it in source
- if you run the admin panel in a container, the SDK runtime and config must exist **inside that container**, not only on the host

Because AWS’s public install page documents install roots rather than a single hard-coded library filename, the safest repo guidance is:

- use the exact PKCS#11 library path visible on the machine that runs the code
- verify that path with the host/container runtime itself before assuming the admin panel or tests can load it

### Bootstrap/configuration expectations

AWS documents two bootstrap styles for Client SDK 5:

- bootstrap using an HSM ENI IP (`-a <ip>`)
- bootstrap using `--cluster-id` plus optional `--region` / `--endpoint`

Operationally, this means:

- cluster reachability and VPC/security-group routing must already be correct
- the customer CA certificate must already be present or explicitly configured
- if the host cannot reach the CloudHSM control plane or HSM ENIs, repo-side changes will not fix that

AWS also documents `--disable-key-availability-check` for cases where you intentionally operate a single-HSM cluster configuration. Treat that as an AWS runtime decision, not a repo default.

## Authentication and session constraints

These are the biggest CloudHSM-specific constraints for this repo:

### 1. Login PIN is `username:password`

CloudHSM does not use a plain opaque PIN string in the way many local fixture modules do. AWS documents `C_Login` PIN input as:

```text
<CU_user_name>:<password>
```

That matters for:

- wrapper examples
- the smoke sample if you adapt it manually
- admin-panel operator instructions
- secret handling and rotation expectations

### 2. Read-only `C_OpenSession` is not supported

AWS explicitly documents that Client SDK 5 rejects read-only session opens with `CKR_FUNCTION_FAILED`.

That matters a lot because many generic PKCS#11 tools assume RO-by-default browsing sessions.

For this repo today:

- **wrapper consumers should open read-write sessions explicitly** when targeting CloudHSM
- the **admin panel now retries a failed read-only open as read-write** for compatibility on browse/lab/session-open flows
- write/destructive semantics are still controlled by the operation itself and the token policy; opening RW does not by itself imply mutation

### 3. Key handles are session-specific

AWS documents that SDK 5 key handles are session-specific and must be reacquired.

Practical implication:

- do not persist CloudHSM key handles across runs and assume they remain valid forever
- use label/ID/object-class lookup and reacquire handles in each new process/session
- this already aligns with how the admin panel and most repo guidance prefer to discover objects dynamically

## Point the core wrapper at CloudHSM

The simplest current integration path is still the direct module load plus an explicit RW session:

```csharp
using Pkcs11Wrapper;

using Pkcs11Module module = Pkcs11Module.Load("/exact/path/from-the-installed-cloudhsm-sdk");
module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

Pkcs11SlotId slotId = module.GetSlotIds(tokenPresentOnly: true)[0];
using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
session.Login(Pkcs11UserType.User, System.Text.Encoding.UTF8.GetBytes("CryptoUser:SecretPassword"));
```

Practical guidance:

- prefer explicit RW sessions on CloudHSM
- reacquire handles in each run instead of caching them long-term
- treat AWS’s supported API list as the contract, not the full PKCS#11 surface exposed by the wrapper
- if you need vendor-defined mechanisms/types, pass raw numeric IDs carefully and validate against a real CloudHSM runtime

## Point the admin panel at CloudHSM

The current admin path is:

1. run `src/Pkcs11Wrapper.Admin.Web` on a machine/container that already has the CloudHSM SDK installed and bootstrapped
2. open the **Devices** page
3. create or edit a device profile with:
   - **Name**: your operational cluster/profile label
   - **PKCS#11 Module Path**: the exact CloudHSM PKCS#11 library path on that host
   - **Default Token Label**: optional token label if your environment exposes a stable label you want to default to
   - **Vendor profile**: **AWS CloudHSM / standard PKCS#11**
   - **Notes**: optional CU/cluster/version/operator reminders
4. use the built-in **Test** action before relying on the profile

### What is improved in this slice

The admin panel now has two CloudHSM-specific readiness improvements:

- a built-in **AWS CloudHSM vendor profile** with setup/auth/scope hints
- a compatibility retry path that upgrades a failed **read-only** session open to **read-write** when the module returns `CKR_FUNCTION_FAILED`

That makes CloudHSM materially more usable in these admin surfaces:

- **Devices** connection testing
- **Slots / Keys** browsing
- **Sessions** tracked-session opening
- **PKCS#11 Lab** browse/inspect/sign/verify/encrypt/decrypt/wrap/read-attribute flows that do not inherently require a different unsupported API

### What not to expect from the admin panel today

Do **not** assume that every admin operation maps cleanly onto CloudHSM SDK 5.

Based on AWS’s documented API list, the following repo admin features should be treated as **not currently assumed supported** on CloudHSM unless a live runtime proves otherwise:

- object copy via `C_CopyObject`
- attribute editing via `C_SetAttributeValue`
- token/bootstrap PIN administration via `C_InitToken`, `C_InitPIN`, `C_SetPIN`
- PKCS#11 v3-only session/message features

The best current admin-panel fit for CloudHSM is therefore:

- device registration
- live slot/mechanism inspection
- key/object discovery and detail reads
- controlled lab diagnostics over the standard documented `C_*` surface
- selected key-management flows that use documented CloudHSM APIs (`C_CreateObject`, `C_GenerateKey`, `C_GenerateKeyPair`, `C_DestroyObject`, `C_WrapKey`, `C_UnWrapKey`)

## Compatibility notes that matter for wrapper/admin usage

### Standard APIs AWS documents

AWS publicly documents support for standard operations including:

- lifecycle / info: `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`
- slot/token/mechanism enumeration
- session open/info/login/logout/close/close-all
- object search + selected object management: `C_CreateObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_FindObjects*`
- crypto: encrypt/decrypt, digest, sign/verify, generate/generate-pair, wrap/unwrap, derive, random

### APIs the current repo should not assume on CloudHSM

AWS’s supported-API page does **not** currently list support for:

- `C_CopyObject`
- `C_SetAttributeValue`
- `C_GetObjectSize`
- `C_InitToken`
- `C_InitPIN`
- `C_SetPIN`
- `C_GetOperationState` / `C_SetOperationState`
- `C_WaitForSlotEvent`
- `C_LoginUser`
- `C_SessionCancel`
- `C_GetInterface*`
- `C_Message*`

So those should remain out-of-scope, capability-gated, or explicitly unclaimed for CloudHSM in this repo.

### Multipart caveat

AWS’s public docs are mixed here:

- the supported-API page lists multipart-style entry points such as `C_DigestUpdate`, `C_SignUpdate`, and friends
- the CloudHSM known-issues page also warns that multipart hashing/signing behavior has historically been problematic and version-sensitive

So the honest repo stance is:

- **do not claim CloudHSM multipart parity from documentation alone**
- validate multipart digest/sign flows only against a real CloudHSM SDK/runtime you actually operate

### AES-GCM caveat

AWS documents important AES-GCM specifics:

- standard `CKM_AES_GCM` expects the IV to be generated by the HSM
- CloudHSM also exposes a vendor-defined `CKM_CLOUDHSM_AES_GCM` safer variant
- AES-GCM buffers have documented size limits/caveats in known issues

For the current repo, that means:

- standard AES-GCM may work for targeted experiments, but payload-size and IV-handling rules are vendor-specific
- vendor-defined AES-GCM is **not** currently a first-class named helper path here; it would require raw numeric use plus real-runtime validation

## What can and cannot be validated locally without a real AWS CloudHSM environment

### What this issue validates locally

Without a real CloudHSM cluster, this repo slice can still validate:

- the documentation/research path itself
- compile/build correctness of the admin-panel compatibility change
- admin test coverage for the RO->RW fallback decision logic
- vendor-profile catalog wiring in the Devices page

### What cannot be validated honestly without a real CloudHSM runtime

Without a live CloudHSM environment, we cannot honestly prove:

- actual module-path resolution for a real installed AWS SDK
- cluster bootstrap success
- CA certificate placement correctness
- CU login behavior with real CloudHSM users
- mechanism exposure for a real cluster/partition/user policy
- multipart behavior on the exact SDK version you deploy
- vendor-defined mechanism usability
- live admin write-path compatibility for create/generate/wrap/unwrap flows
- end-to-end smoke or regression success against AWS CloudHSM

## Why there is no checked-in CloudHSM regression profile yet

The repo already has a generic vendor lane, but CloudHSM currently needs a more careful capability contract because:

- SDK 5 rejects RO sessions
- AWS does not document support for several admin/provisioning calls currently assumed elsewhere in the repo (`C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_CopyObject`, `C_SetAttributeValue`, `C_GetOperationState`, etc.)
- smoke/vendor-regression flows would need CloudHSM-aware capability gating before they could be described as reliable

That is why this issue delivers:

- solid CloudHSM documentation
- admin-panel readiness improvements
- a clearer support boundary

rather than pretending the existing full regression stack is already CloudHSM-proven.

## Recommended real-environment validation order

When a real CloudHSM environment is available, validate in this order:

1. **module load + initialize + slot listing**
2. **RW session open + `username:password` login**
3. **object search by label/ID**
4. **mechanism inventory from the live slot**
5. **single-part sign/verify and encrypt/decrypt**
6. **generate/create/destroy flows with a disposable test user/object namespace**
7. only then evaluate multipart, wrap/unwrap, and any vendor-defined mechanisms

That sequence matches the repo’s current support depth far better than trying to start with the most advanced CloudHSM-specific paths.
