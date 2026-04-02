# Google Cloud HSM integration guide

See also:

- `docs/google-cloud-hsm-compatibility-audit.md` for the conservative compatibility audit against Google public documentation
- `docs/compatibility-matrix.md` for the repo-wide support summary and current limits
- `docs/vendor-regression.md` for why there is not yet a checked-in Google Cloud HSM vendor-regression profile

## Purpose

This guide turns the Google Cloud HSM research from issue #67 into a practical setup path for the current repository.

It is intentionally conservative:

- it describes the official Google path for PKCS#11 consumption of Cloud HSM-backed keys
- it shows the practical current path for the **wrapper** and **admin panel**
- it documents the Linux/Windows/config/auth constraints that matter operationally
- it distinguishes what is **ready now**, what is **blocked by abstraction boundaries**, and what still needs a **real Google Cloud environment** to validate honestly

## What “Google Cloud HSM support” means in this repo today

The key design fact is that **Google Cloud HSM is not exposed to this repo as a direct vendor HSM client SDK**.

The official Google story is:

- Cloud HSM keys live behind **Cloud KMS**
- Google publishes **kmsp11**, a PKCS#11 v2.40 library that translates PKCS#11 calls into Cloud KMS operations
- applications that need PKCS#11 interact with **kmsp11** (`libkmsp11.so` / `kmsp11.dll`), not with a direct network-attached HSM client in the AWS/Thales sense

So the practical support story here is:

### Supported well enough to use now

- explicit kmsp11 module-path loading through `Pkcs11Module.Load(...)`
- standard module / slot / token / mechanism enumeration over kmsp11
- object search and attribute reads through `C_FindObjects*` / `C_GetAttributeValue`
- standard sign / verify / encrypt / decrypt flows that kmsp11 documents as supported for Cloud KMS-backed keys
- destroy flows via `C_DestroyObject`
- admin-panel device profiles via the new **Google Cloud KMS / Cloud HSM via kmsp11** vendor profile
- admin-panel guardrails that keep unsupported generic-token flows honest for Google profiles

### Important boundaries

- this repo does **not** implement Google Cloud control-plane operations such as key-ring creation, IAM management, service-account bootstrap, policy administration, or broader Cloud KMS lifecycle tasks
- this repo does **not** currently provide a checked-in Google vendor-regression lane, because kmsp11 needs real Cloud KMS configuration/auth and its supported PKCS#11 surface is intentionally narrower than a classic token
- the current wrapper surface does **not** expose kmsp11's `C_Initialize` `pReserved` config-path channel, so the practical current path is to set `KMS_PKCS11_CONFIG` on the host that runs the wrapper/admin app
- the current generic admin key-generation forms are **not** a clean fit for kmsp11 key creation, because Google documents vendor-specific `CKA_KMS_*` template attributes for `C_GenerateKey` / `C_GenerateKeyPair`

## Google Cloud model that matters here

From Google's public docs, the key integration facts are:

- Cloud HSM is a **Cloud KMS protection level** rather than a separate customer-managed network HSM client runtime
- the official PKCS#11 path is the **Cloud KMS PKCS#11 library (`kmsp11`)**
- kmsp11 is configured by:
  - passing the config-file path in `C_Initialize` `pReserved`, or
  - setting `KMS_PKCS11_CONFIG=/path/to/config.yaml`
- each configured `tokens:` entry in the YAML file becomes a PKCS#11 token/slot view, typically backed by a Cloud KMS key ring
- authentication uses **Google service account credentials / Google auth** rather than a classic on-device token PIN model
- `C_Login` exists only for compatibility; Google documents that login is optional and any supplied PIN is ignored

## Prerequisites

Before pointing this repo at Google Cloud HSM through kmsp11, make sure:

1. the host or container that runs the code already has the official **kmsp11** library available
2. the host has a valid kmsp11 **YAML config file** with the intended `tokens:` entries
3. the process has working **Google authentication** (typically a service account / ADC-backed runtime)
4. the service account has the IAM permissions needed for the operations you intend to run
5. the process can resolve the intended PKCS#11 module path from that installed kmsp11 runtime
6. you understand that token/slot/object visibility comes from Cloud KMS configuration and IAM, not from local HSM provisioning tools

### Authentication expectations

Google's kmsp11 user guide states that the library authenticates with **service account credentials** and requires IAM permissions including:

- `cloudkms.cryptoKeys.list`
- `cloudkms.cryptoKeyVersions.list`
- `cloudkms.cryptoKeyVersions.viewPublicKey`
- `cloudkms.cryptoKeyVersions.useToDecrypt` or `cloudkms.cryptoKeyVersions.useToSign` depending on the key usage
- `cloudkms.cryptoKeys.create` if you intend to create keys
- `cloudkms.cryptoKeyVersions.destroy` if you intend to destroy keys

For local/dev hosts, the practical auth model is usually Application Default Credentials or an explicitly supplied service-account credential chain on the machine/container that runs the process.

## Linux and Windows setup expectations

### Runtime/library layout

The repo does not auto-discover kmsp11 for you. You must provide the exact PKCS#11 module path that the current host can load.

Practical guidance:

- on Linux, Google's release packages expose **`libkmsp11.so`**
- on Windows, Google's release packages expose **`kmsp11.dll`**
- if the admin panel runs in a container, the library and its config/auth context must exist **inside that container**, not only on the host

### Published platform expectations

Google's kmsp11 user guide documents:

- **Linux**: `libkmsp11.so` is compatible with Linux distributions that provide **glibc 2.17 or newer**
- **Windows**: supported on **Windows Server 2012 R2 / Windows 8.1 x64 and newer**
- **Older Windows versions**: prior to Windows 10 / Server 2016, the **Visual C++ 2022 x64 Redistributable** must already be installed

## kmsp11 configuration expectations

Google documents two ways to supply the kmsp11 config file path:

- `C_Initialize` `pReserved`
- `KMS_PKCS11_CONFIG`

The current repo support slice should assume the **environment-variable path**:

```bash
export KMS_PKCS11_CONFIG=/secure/path/kmsp11.yaml
```

Why this matters:

- `Pkcs11Wrapper` already supports standard initialize flags and mutex callbacks
- but the current API surface does **not** yet expose a direct managed way to populate kmsp11's `pReserved` config path
- so the cleanest current wrapper/admin path is to set `KMS_PKCS11_CONFIG` before the process starts

Google's guide also requires the config file to be writable only by the owner.

### Sample shape

Google's documented sample looks like this:

```yaml
---
tokens:
  - key_ring: "projects/my-project/locations/us/keyRings/my-key-ring"
    label: "my key ring"
log_directory: "/var/log/kmsp11"
```

Practical implications for this repo:

- slot numbering is driven by the `tokens:` list order
- token labels come from the YAML `label:` field or the underlying key-ring identity
- the admin panel should be treated as a **consumer** of this prepared view, not as the place that authors it

## Point the core wrapper at Google Cloud HSM

The simplest current integration path is the standard module load plus a host-provided config path:

```csharp
using Pkcs11Wrapper;

Environment.SetEnvironmentVariable("KMS_PKCS11_CONFIG", "/secure/path/kmsp11.yaml");

using Pkcs11Module module = Pkcs11Module.Load("/exact/path/to/libkmsp11.so");
module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

Pkcs11SlotId slotId = module.GetSlotIds(tokenPresentOnly: true)[0];
using Pkcs11Session session = module.OpenSession(slotId, readWrite: false);

// Optional for compatibility-oriented clients; Google documents that login is not required
// and any supplied PIN is ignored.
session.Login(Pkcs11UserType.User, System.Text.Encoding.UTF8.GetBytes("ignored-by-kmsp11"));
```

Practical guidance:

- set `KMS_PKCS11_CONFIG` before the process starts when using the current repo surface
- treat kmsp11 as the PKCS#11 boundary and Cloud KMS as the real backing system
- prefer label/ID-based lookup over assumptions about locally provisioned token objects
- remember that Google documents a narrower supported PKCS#11 surface than a classic local token

## Point the admin panel at Google Cloud HSM

The current admin path is:

1. run `src/Pkcs11Wrapper.Admin.Web` on a machine/container that already has kmsp11 plus Google auth configured
2. set `KMS_PKCS11_CONFIG` in that process environment before the app starts
3. open the **Devices** page
4. create or edit a device profile with:
   - **Name**: your operational Google/KMS profile label
   - **PKCS#11 Module Path**: the exact kmsp11 library path on that host (`libkmsp11.so` / `kmsp11.dll`)
   - **Default Token Label**: optional label matching your kmsp11 token config
   - **Vendor profile**: **Google Cloud KMS / Cloud HSM via kmsp11**
   - **Notes**: optional project/location/key-ring/operator breadcrumbs
5. use the built-in **Test** action before relying on the profile

### What is improved in this slice

The admin panel now has two Google-specific readiness improvements:

- a built-in **Google Cloud KMS / Cloud HSM via kmsp11** vendor profile with config/auth/scope hints
- guardrails that disable or explicitly reject generic admin flows that do not map honestly to kmsp11 today (`C_CreateObject`, `C_CopyObject`, `C_SetAttributeValue`, and the current generic AES/RSA generation forms)

That makes the Google path materially clearer in these admin surfaces:

- **Devices** connection testing
- **Slots / Keys** browsing and capability inspection
- **Sessions** / **PKCS#11 Lab** diagnostics that stay inside kmsp11's documented standard surface
- controlled destroy and read-oriented workflows once the environment is real

### What not to expect from the admin panel today

Do **not** assume that every generic admin operation maps cleanly onto kmsp11.

Based on Google's documented function table and generation-template rules, the following admin features should be treated as **not currently supported on the generic admin surface** for Google profiles:

- raw AES import via `C_CreateObject`
- generic object copy via `C_CopyObject`
- generic attribute editing via `C_SetAttributeValue`
- generic AES/RSA generation forms that do not emit the required `CKA_KMS_*` attributes
- wrap / unwrap / derive / PIN-administration workflows
- Cloud KMS provisioning/control-plane work such as key-ring setup or IAM changes

The best current admin-panel fit for Google is therefore:

- device registration
- live slot/mechanism inspection
- object discovery and detail reads
- selected standard diagnostics in the PKCS#11 Lab
- honest documentation of the wrapper/admin boundary

## Compatibility notes that matter for wrapper/admin usage

### Standard APIs Google documents as supported

Google's kmsp11 user guide documents support for standard operations including:

- lifecycle / info: `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`
- slot/token/mechanism enumeration
- session open/info/login/logout/close/close-all
- object search + selected object access: `C_DestroyObject`, `C_GetAttributeValue`, `C_FindObjects*`
- crypto: encrypt/decrypt, sign/verify, multipart encrypt/decrypt/sign/verify variants
- creation flows: `C_GenerateKey`, `C_GenerateKeyPair` with Google-specific template constraints
- random: `C_GenerateRandom`

### APIs the current repo should not assume on Google

Google's kmsp11 user guide marks these as unsupported:

- `C_InitToken`
- `C_InitPIN`
- `C_SetPIN`
- `C_CreateObject`
- `C_CopyObject`
- `C_GetObjectSize`
- `C_SetAttributeValue`
- `C_Digest*`
- `C_GetOperationState` / `C_SetOperationState`
- `C_WrapKey`
- `C_UnwrapKey`
- `C_DeriveKey`
- `C_WaitForSlotEvent`
- `C_GetFunctionStatus` / `C_CancelFunction`

So those should remain out-of-scope, capability-gated, or explicitly unclaimed for Google Cloud HSM in this repo.

### Key-generation caveat

Google documents that:

- `C_GenerateKey` requires `CKA_LABEL` and **`CKA_KMS_ALGORITHM`**
- `C_GenerateKeyPair` requires a private-key template with **`CKA_LABEL`** and **`CKA_KMS_ALGORITHM`**, and a public template must not be specified
- optional `CKA_KMS_PROTECTION_LEVEL` / `CKA_KMS_CRYPTO_KEY_BACKEND` fields affect HSM vs single-tenant HSM behavior

That means the **wrapper** is still a reasonable fit for Google generation work if the caller supplies the right raw PKCS#11 attributes, but the **current generic admin forms are not yet the right abstraction** for that path.

### Object visibility caveat

Google documents that usable key versions must be:

- in purpose `ASYMMETRIC_SIGN`, `ASYMMETRIC_DECRYPT`, `RAW_ENCRYPT_DECRYPT`, or `MAC`
- in protection level `HSM` or `HSM_SINGLE_TENANT` (or `SOFTWARE` only if explicitly enabled)
- in state `ENABLED`

Keys outside that envelope are ignored by kmsp11 and therefore simply do not appear like a classic local token object set.

### Caching caveat

Google documents that kmsp11 reads configured key-ring contents during initialization and caches them in memory.

Practical implication:

- `C_Initialize` latency scales with configured key volume
- newly created/changed keys may remain stale until refresh or reinitialize
- admin operators should not assume immediate reflection of Cloud KMS control-plane changes unless the config/runtime is set up for refresh

## What can vs cannot be validated locally without real Google Cloud access

### What can be validated locally in issue #67

Without real Google Cloud access, this issue could validate:

- documentation correctness against Google public docs
- compile/build correctness of the admin-panel guardrails and vendor-profile wiring
- unit-test coverage of the Google vendor-profile catalog wiring
- repo-level analysis of where the current abstraction boundary is honest vs misleading

### What cannot be validated honestly without real Google Cloud access

Without a real Google-authenticated environment, this issue could **not** honestly validate:

- kmsp11 end-to-end initialization against a real config file and real Cloud KMS inventory
- actual IAM/auth failures or success paths
- real Linux/Windows host deployment behavior beyond documented prerequisites
- real slot/token/object exposure for a live key ring
- real sign/verify/encrypt/decrypt behavior against HSM-backed Cloud KMS keys
- real create/destroy behavior against Google Cloud HSM-backed keys
- real admin-panel end-to-end behavior against kmsp11 and Google Cloud services

## Practical conclusion

The current repo should describe Google Cloud HSM support as:

- **indirect PKCS#11 support via Cloud KMS + kmsp11**
- **good wrapper-level fit for standard documented kmsp11 flows**
- **admin-panel-ready enough for device registration, inspection, diagnostics, and honest boundary-setting**
- **not a blanket claim that the current generic admin key-management forms are Google-ready**
- **not yet live-validated without a real Google Cloud environment**

That is the honest and useful first support slice for issue #67.
