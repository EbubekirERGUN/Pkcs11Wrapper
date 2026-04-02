# OCI Dedicated KMS integration guide

See also:

- `docs/oci-dedicated-kms-compatibility-audit.md` for the conservative compatibility audit against Oracle public documentation
- `docs/compatibility-matrix.md` for the repo-wide support summary and current limits
- `docs/vendor-regression.md` for why there is not yet a checked-in OCI Dedicated KMS vendor-regression profile

## Purpose

This guide turns the Oracle Cloud Infrastructure HSM research from issue #68 into a practical setup path for the current repository.

It is intentionally conservative:

- it clarifies which **OCI product boundary** is the real fit for `Pkcs11Wrapper`
- it shows the practical current path for the **wrapper** and **admin panel**
- it documents the Linux/Windows/client/setup/auth constraints that matter operationally
- it distinguishes what is **ready now**, what fits only behind a **different abstraction boundary**, and what still needs a **real OCI environment** to validate honestly

## What “OCI HSM support” means in this repo today

The most important design fact is that **OCI is not one single PKCS#11 story**.

Oracle’s public docs currently describe three materially different paths:

1. **OCI Dedicated KMS**
   - a managed, single-tenant HSM partition service
   - explicitly documented with a **PKCS#11 v2.40** client library
   - the only OCI path that currently looks like a **direct PKCS#11 fit** for this repo

2. **OCI Vault / Key Management / virtual private vaults**
   - OCI-managed vault/key resources consumed through OCI APIs, CLI, Console, and OCI SDKs
   - not documented in the reviewed material as a host-local PKCS#11 module for generic apps like this repo
   - better understood as an **OCI API/SDK integration boundary**, not a direct `Pkcs11Wrapper` module-path scenario

3. **OCI External KMS / HYOK style integrations**
   - key material stays in a third-party key management system outside OCI
   - this is a **different control-plane/integration problem**, not an OCI-native PKCS#11 target for the current admin panel

So the practical repo support story is:

### Supported well enough to use now

- explicit Oracle PKCS#11 module-path loading through `Pkcs11Module.Load(...)` when the host already has the **OCI Dedicated KMS Linux client** installed
- standard module / slot / token / mechanism enumeration against the installed OCI PKCS#11 module
- CU login via standard `C_Login` using the documented `username:password` format
- standard object discovery / attribute-read / live diagnostics flows that work against the real module runtime
- standard encrypt/decrypt and sign/verify experiments through the mechanisms Oracle publicly documents
- admin-panel device profiles via the new **Oracle OCI Dedicated KMS / standard PKCS#11** vendor profile

### Important boundaries

- this repo does **not** implement OCI control-plane provisioning such as HSM-cluster creation, network/certificate bootstrap, or Oracle user/partition administration
- this repo does **not** currently claim a direct PKCS#11 path for **OCI Vault** or **virtual private vault** usage; those remain better treated as OCI API/SDK integrations
- Oracle’s reviewed docs currently document **PKCS#11 client packages on Oracle Linux** and **CNG/KSP on Windows**; this repo therefore treats the direct OCI PKCS#11 fit as **Linux-first**, not as a blanket Windows story
- this repo does **not** currently provide a checked-in OCI Dedicated KMS smoke or vendor-regression profile because no live OCI HSM environment was available during issue #68

## OCI product mapping that matters here

### 1. OCI Dedicated KMS = direct PKCS#11 fit

Oracle documents Dedicated KMS as a managed, highly available service that gives the customer a **single-tenant HSM partition** and explicitly says that PKCS#11 can be used for cryptographic operations **without the need for OCI APIs or modules**.

That is the path that maps naturally to `Pkcs11Wrapper`.

### 2. OCI Vault / Key Management = different abstraction boundary

Oracle’s broader Vault / Key Management docs describe OCI vaults, OCI key resources, protection modes, and OCI-native key operations through OCI service surfaces.

That means the correct integration boundary for standard Vault usage is:

- application -> OCI SDK / CLI / REST / service integration

not:

- application -> host-local PKCS#11 module

So the current repo should **not** describe generic OCI Vault support as if it were already a direct PKCS#11 device profile.

### 3. Windows CNG/KSP = different client surface

Oracle also documents Dedicated KMS support for **Windows CNG and KSP**.

That is useful operationally, but it is **not the same thing as a documented Windows PKCS#11 module path** for this repo. `Pkcs11Wrapper` and the current admin panel consume PKCS#11 modules, not Windows CNG/KSP providers.

## OCI Dedicated KMS model that matters here

From Oracle’s public documentation, the key integration facts are:

- Dedicated KMS is a **single-tenant HSM partition** service
- the PKCS#11 library is documented as **PKCS#11 v2.40**
- getting started requires:
  1. provisioning an HSM cluster
  2. installing client components
  3. using the PKCS#11 library for cryptographic operations
- Oracle documents a dedicated Linux PKCS#11 package that depends on the **OCI HSM client** and a running **`client_daemon`**
- the Linux PKCS#11 libraries are installed under **`/opt/oci/hsm/lib`**
- PKCS#11 logging is configured through **`/opt/oci/hsm/data/pkcs11.cfg`**
- client connectivity/configuration depends on client cert/key material such as **`cert-c`**, **`pkey-c`**, and **`partitionOwnerCert.pem`** plus cluster hostname/port configuration in the client daemon config
- Oracle documents PKCS#11 authentication as **CU login** through `C_Login` using **`<CU_user_name>:<password>`**
- customers are responsible for synchronizing users and keys across all replicas in the HSM cluster; if that drift exists, application availability can be affected

## Prerequisites

Before pointing this repo at OCI Dedicated KMS, make sure:

1. an **OCI Dedicated KMS HSM cluster** already exists
2. the host that runs the code already has the **OCI HSM client** installed
3. the host also has the **OCI PKCS#11 package** installed
4. the host has the required client certificate/key material available (`cert-c`, `pkey-c`, `partitionOwnerCert.pem`)
5. `client_daemon.cfg` is already configured with the real cluster hostname/port and certificate paths
6. the **`client_daemon`** is running successfully before the .NET process starts
7. you have a valid **crypto user (CU)** for PKCS#11 login
8. the process can resolve the exact OCI PKCS#11 shared library path from the installed client runtime

## Linux and Windows setup expectations

### Supported client operating systems Oracle documents

Oracle’s reviewed docs list supported client-component operating systems as:

- **Oracle Linux 7**
- **Oracle Linux 8**
- **Oracle Linux 9**
- **Windows Server 2019**

### Direct PKCS#11 path in this repo: treat it as Linux-first

For the direct PKCS#11 path, the Oracle docs reviewed for this issue document:

- Linux PKCS#11 installation through `oci-hsm-pkcs11`
- a dependency on `oci-hsm-client-<version>.x86_64.rpm`
- Linux PKCS#11 libraries under **`/opt/oci/hsm/lib`**
- Linux PKCS#11 config under **`/opt/oci/hsm/data/pkcs11.cfg`**

That is the clean practical fit for `Pkcs11Wrapper` and the admin panel.

### Windows path in Oracle docs: CNG/KSP, not the current repo boundary

Oracle’s reviewed Windows docs focus on:

- the Windows client service
- CNG / KSP provider registration and use
- the `n3fips_password=<username>:<password>` system environment variable for Windows provider usage

Those are meaningful Oracle client/runtime features, but they do **not** currently give this repo a documented Windows PKCS#11 module story.

So the conservative current repo stance is:

- **Linux**: direct OCI Dedicated KMS PKCS#11 support path
- **Windows**: Oracle-documented support exists through **CNG/KSP**, but that is **outside the current PKCS#11 wrapper/admin abstraction boundary**

## Client/bootstrap expectations on Linux

Oracle’s reviewed Linux docs show a multi-step client contract:

1. install the OCI HSM client package
2. copy `pkey-c`, `cert-c`, and `partitionOwnerCert.pem` into **`/opt/oci/hsm/data`**
3. configure **`/opt/oci/hsm/data/client_daemon.cfg`** with:
   - certificate paths
   - CA path
   - owner certificate path
   - cluster hostname
   - cluster port
   - reconnect/logging settings
4. start the daemon:

```bash
/opt/oci/hsm/bin/client_daemon /opt/oci/hsm/data/client_daemon.cfg
```

5. install the PKCS#11 package
6. optionally tune PKCS#11 logging in **`/opt/oci/hsm/data/pkcs11.cfg`**
7. only then point the .NET app at the resolved PKCS#11 library under **`/opt/oci/hsm/lib`**

Operationally, this means:

- if the daemon is not configured/running, repo-side code changes will not fix connectivity
- if the host/container does not have the OCI client runtime inside it, the admin panel cannot use the host installation magically from outside that runtime boundary
- the exact `.so` path should stay in app configuration / device profile rather than being hard-coded in source

## Authentication and session expectations

### 1. PKCS#11 login is CU-based and uses `username:password`

Oracle documents `C_Login` input for the PKCS#11 library as:

```text
<CU_user_name>:<password>
```

That matters for:

- wrapper examples
- admin-panel operator instructions
- secret handling expectations
- local lab or smoke attempts against a real OCI environment

### 2. Key visibility is CU-scoped

Oracle documents that the application runs as a **crypto user (CU)** and can view/manage only keys that the CU owns or that are shared with that CU.

Practical implication:

- “missing” keys may be an OCI user/ownership/sharing issue rather than a wrapper bug
- object discovery in the admin panel will reflect the real CU scope, not a global appliance inventory

### 3. Replica synchronization matters operationally

Oracle documents that customers are responsible for synchronizing users and keys across all replicas in the HSM cluster.

Practical implication:

- module connectivity alone is not enough to guarantee availability
- if users/keys are not consistently present across replicas, session success and object visibility can drift in ways the repo cannot mask

## Point the core wrapper at OCI Dedicated KMS

The practical current integration path is the standard module load against the installed Linux PKCS#11 library:

```csharp
using Pkcs11Wrapper;

using Pkcs11Module module = Pkcs11Module.Load("/exact/path/from-the-installed-oci-pkcs11-library.so");
module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

Pkcs11SlotId slotId = module.GetSlotIds(tokenPresentOnly: true)[0];
using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
session.Login(Pkcs11UserType.User, System.Text.Encoding.UTF8.GetBytes("CryptoUser:SecretPassword"));
```

Practical guidance:

- use the **exact** `.so` path that exists on the Oracle Linux host/container running the process
- do not assume a specific filename from repo docs if Oracle’s installed package layout differs on your host
- prefer validating slot/mechanism exposure from the live module before assuming a generic mechanism baseline
- treat object visibility as CU/policy dependent

## Point the admin panel at OCI Dedicated KMS

The current admin path is:

1. run `src/Pkcs11Wrapper.Admin.Web` on an **Oracle Linux** machine/container that already has the OCI client runtime and daemon working
2. open the **Devices** page
3. create or edit a device profile with:
   - **Name**: your operational OCI cluster/profile label
   - **PKCS#11 Module Path**: the exact OCI PKCS#11 library path on that host under `/opt/oci/hsm/lib`
   - **Default Token Label**: optional token label if your environment exposes a stable label you want to default to
   - **Vendor profile**: **Oracle OCI Dedicated KMS / standard PKCS#11**
   - **Notes**: optional cluster/partition/CU/client-version/operator breadcrumbs
4. use the built-in **Test** action before relying on the profile

### What is improved in this slice

The admin panel now has a built-in **Oracle OCI Dedicated KMS / standard PKCS#11** vendor profile that keeps the most important Oracle-specific guidance visible:

- Dedicated KMS is the direct PKCS#11 fit
- Linux PKCS#11 runtime/daemon prerequisites must already exist on the host
- Windows Oracle guidance is currently CNG/KSP rather than the PKCS#11 boundary this app consumes
- OCI Vault/control-plane/user-admin boundaries stay outside the admin UI

### What not to expect from the admin panel today

Do **not** expect the admin panel to:

- provision an OCI HSM cluster
- create or synchronize OCI HSM users across replicas
- generate/sign client certificates or bootstrap `cert-c` / `pkey-c` / `partitionOwnerCert.pem`
- configure or launch the OCI client daemon for you
- consume Windows CNG/KSP providers in place of a PKCS#11 module
- act as a replacement for OCI Vault / KMS APIs when the real integration boundary is not direct PKCS#11

## Compatibility notes that matter for wrapper/admin usage

### Publicly documented mechanism families reviewed for this issue

Oracle’s public PKCS#11 docs reviewed here explicitly document encrypt/decrypt mechanisms such as:

- `CKM_AES_CBC`
- `CKM_AES_CBC_PAD`
- `CKM_AES_ECB`
- `CKM_AES_CTR`
- `CKM_AES_GCM`
- `CKM_RSA_PKCS`
- `CKM_RSA_PKCS_OAEP`

The reviewed docs also explicitly document sign/verify mechanisms such as:

- RSA PKCS / PSS families
- ECDSA families
- HMAC families

### What this repo should still keep conservative

Unlike some other vendors, the Oracle public docs reviewed for this issue did **not** provide a single exhaustive function-by-function supported-API matrix that cleanly maps every `C_*` entry point the repo exposes.

So the honest current stance is:

- standard direct PKCS#11 integration for OCI Dedicated KMS looks **plausible and practical**
- wrapper/admin support should stay focused on **standard module loading, session/login, object discovery, and live diagnostics** unless a real OCI runtime proves broader behavior
- generic advanced flows that depend on vendor policy or unreviewed API details should be treated as **real-runtime validation items**, not as paper guarantees from docs alone

### PKCS#11 v3 remains unclaimed for OCI

Oracle’s reviewed Dedicated KMS PKCS#11 docs describe a **PKCS#11 v2.40** library.

That means the current repo should **not** infer OCI support for PKCS#11 v3 interface discovery, message APIs, `C_LoginUser`, or `C_SessionCancel` from repo capability alone.

## What can and cannot be validated locally without a real OCI environment

### What this issue validates locally

Without a real OCI Dedicated KMS environment, this repo slice can still validate:

- the Oracle product mapping itself
- documentation correctness against Oracle public docs
- compile/build correctness of the new Oracle vendor-profile wiring
- unit-test coverage for the admin vendor-profile catalog entry

### What cannot be validated honestly without real OCI access

Without a live OCI environment, we cannot honestly prove:

- real OCI client installation behavior on the target host
- correct client certificate / owner certificate setup
- successful daemon connectivity to a real HSM cluster
- real CU login behavior and key visibility
- real slot/token/mechanism exposure for a prepared cluster
- actual object-management behavior against OCI Dedicated KMS policy/runtime
- end-to-end admin-panel behavior against a real OCI HSM environment
- whether any existing vendor-regression flow assumptions need OCI-specific capability gating

## Why there is no checked-in OCI Dedicated KMS regression profile yet

The repo already has a generic vendor lane, but OCI Dedicated KMS still needs real-environment proof before a named checked-in profile would be honest.

Reasons:

- the direct PKCS#11 path depends on a real OCI cluster, client cert/key material, and a running daemon
- the reviewed public docs do not publish the same kind of exhaustive supported-API matrix that would let the repo claim broad compatibility from documentation alone
- Windows Oracle docs currently describe CNG/KSP rather than a documented Windows PKCS#11 path for this repo
- no live OCI environment was available during issue #68 to validate the current vendor lane contract end to end

That is why this issue delivers:

- solid OCI product-mapping and integration documentation
- admin-panel vendor-profile guidance
- a clearer direct-vs-indirect support boundary

rather than pretending OCI-backed regression automation already exists.

## Recommended real-environment validation order

When a real OCI Dedicated KMS environment is available, validate in this order:

1. **client daemon connectivity + module load + initialize**
2. **slot/token listing from the live module**
3. **CU login with `username:password`**
4. **object search / attribute reads for known test objects**
5. **mechanism inventory from the live slot**
6. **single-part encrypt/decrypt and sign/verify using documented mechanisms**
7. only then evaluate create/generate/import/destroy and any broader regression expectations

That sequence matches the current support depth much better than claiming blanket OCI parity without live-runtime evidence.
