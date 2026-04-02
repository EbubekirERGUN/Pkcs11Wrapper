# IBM Cloud Hyper Protect Crypto Services integration guide

See also:

- `docs/ibm-cloud-hpcs-compatibility-audit.md` for the conservative compatibility audit against IBM public documentation
- `docs/compatibility-matrix.md` for the repo-wide support summary and current limits
- `docs/vendor-regression.md` for why there is not yet a checked-in IBM HPCS vendor-regression profile

## Purpose

This guide turns the IBM Cloud Hyper Protect Crypto Services research from issue #69 into a practical setup path for the current repository.

It is intentionally conservative:

- it describes how to use the **direct EP11 PKCS#11 client path** that fits `Pkcs11Wrapper`
- it explicitly separates that from IBM's **GREP11 gRPC** path
- it documents the Linux/Windows/client/setup/auth constraints that matter operationally
- it distinguishes what is **ready now**, what stays outside the current abstraction boundary, and what still needs **real IBM Cloud access** to validate honestly

## What “IBM Cloud HPCS support” means in this repo today

The most important design fact is that **IBM HPCS is not one single integration surface**.

IBM publishes at least two relevant cryptographic access paths:

1. **Direct PKCS#11 through the EP11 client library**
   - local client library loaded by the application
   - configured through `grep11client.yaml`
   - the practical fit for `Pkcs11Wrapper` and the current admin panel

2. **GREP11 API**
   - a separate gRPC-based API surface
   - useful in its own right, but a different abstraction boundary
   - **not** the path this repo currently consumes

So the practical repo support story is:

### Supported well enough to use now

- explicit IBM HPCS PKCS#11 module-path loading through `Pkcs11Module.Load(...)`
- standard module / slot / token / mechanism enumeration against IBM's EP11 PKCS#11 library
- standard session/login/logout flows against IBM's IAM-backed PKCS#11 user model
- standard object discovery / attribute reads / create / copy / destroy flows where the live IBM module allows them
- standard generate / wrap / unwrap / derive flows where the live IBM module and policy allow them
- admin-panel device profiles via the new **IBM Cloud HPCS / EP11 PKCS#11** vendor profile
- admin-panel operator guidance that keeps Linux/auth/boundary expectations visible

### Important boundaries

- this repo does **not** implement IBM Cloud control-plane tasks such as instance creation, initialization, service-ID creation, endpoint discovery, or certificate upload
- this repo does **not** implement the separate **GREP11 gRPC** client surface
- this repo does **not** currently provide a checked-in IBM HPCS smoke or vendor-regression profile because no live HPCS environment was available during issue #69
- the reviewed public IBM client packaging for the direct PKCS#11 path is **Linux-only**, so the current repo support claim is Linux-first rather than a blanket Windows story

## IBM model that matters here

From the reviewed IBM public docs, the key integration facts are:

- IBM HPCS exposes an **Enterprise PKCS#11 (EP11)** endpoint for the direct PKCS#11 client path
- the client uses a local shared library plus a `grep11client.yaml` file
- the config binds together:
  - the EP11 endpoint URL + port
  - TLS / optional mutual TLS settings
  - storage / remote-store settings
  - user definitions
  - IAM-backed authentication
  - keystore UUIDs and optional authenticated-keystore passwords
- IBM documents three practical PKCS#11 user identities:
  - **SO user**
  - **normal user**
  - **anonymous user**
- IBM documents `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_Login`, key generation, wrap/unwrap, derive, and operation-state functions in the standard PKCS#11 API reference
- IBM publishes the HPCS PKCS#11 client library in the `IBM-Cloud/hpcs-pkcs11` repo and states the direct client is currently supported only on **Linux GLIBC** distros for **amd64** and **s390x**

## Prerequisites

Before pointing this repo at IBM HPCS, make sure:

1. a real **IBM Cloud HPCS** service instance already exists
2. the instance is already initialized and operational from IBM's perspective
3. the host or container that runs the code already has the IBM **HPCS PKCS#11 client library** available
4. the host also has a valid **`grep11client.yaml`** configuration file
5. the operator already knows the real:
   - EP11 endpoint URL
   - EP11 port
   - private/public keystore UUIDs
   - relevant IBM IAM service ID API keys
6. if using optional authenticated keystores, the operator already has the required **6-8 character** keystore password material
7. if using optional mutual TLS, the operator already has the client certificate and private key material available on the runtime host
8. the process can resolve the exact IBM PKCS#11 shared-library path from the installed client runtime

## Linux and Windows expectations

### Direct PKCS#11 path: Linux only in reviewed public packaging

IBM's reviewed public client repo states that the HPCS PKCS#11 library is currently supported only on:

- **Linux GLIBC** distributions
- **amd64** and **s390x**

Practical implication for this repo:

- run the wrapper/admin direct PKCS#11 path on Linux
- if you use containers, the IBM client library, config file, and any certificate material must exist **inside the container**
- do **not** assume Alpine compatibility; IBM's public note is GLIBC-only

### Windows expectation for this repo today

The reviewed public material for issue #69 did **not** give a direct Windows PKCS#11 client packaging path for HPCS that matches the current wrapper/admin boundary.

So the conservative current repo stance is:

- **Linux**: direct IBM HPCS PKCS#11 support path
- **Windows**: no current direct-PKCS#11 support claim for this repo boundary

## Configuration-file expectations

IBM documents a `grep11client.yaml` file that normally lives in:

- `/etc/ep11client`

or is referenced through:

- `EP11CLIENT_CFG=/full/path/to/custom-config.yaml`

That file is not optional for the direct client path.

A trimmed example shape from the reviewed IBM docs looks like this:

```yaml
iamcredentialtemplate: &defaultiamcredential
  enabled: true
  endpoint: "https://iam.cloud.ibm.com"

sessionauthtemplate: &defaultsessionauth
  enabled: false
  tokenspaceIDPassword:

tokens:
  0:
    grep11connection:
      address: "<instance_ID>.ep11.<region>.hs-crypto.appdomain.cloud"
      port: "<EP11_port>"
      tls:
        enabled: true
        mutual: false
        cacert:
        certfile:
        keyfile:
    storage:
      remotestore:
        enabled: true
    users:
      0:
        name: "<SO_user_name>"
        iamauth: *defaultiamcredential
      1:
        name: "<normal_user_name>"
        tokenspaceID: "<private_keystore_uuid>"
        iamauth: *defaultiamcredential
        sessionauth: *defaultsessionauth
      2:
        name: "<anonymous_user_name>"
        tokenspaceID: "<public_keystore_uuid>"
        iamauth:
          <<: *defaultiamcredential
          apikey: "<anonymous_user_apikey>"
        sessionauth: *defaultsessionauth
```

What matters operationally:

- the **anonymous** user API key lives in config
- the **SO** and **normal** user identities are still part of the PKCS#11 login story
- the EP11 endpoint, keystore UUIDs, and any optional mTLS/session-auth settings are host/runtime configuration, not app source code

## Authentication and session expectations

### 1. IBM's direct PKCS#11 path is IAM-backed, not a generic local token PIN story

IBM documents PKCS#11 user setup around IBM IAM service IDs and API keys.

Practical implication:

- operators should think in terms of **service ID API keys** and IBM access policy setup
- for the direct PKCS#11 path, **SO** and **normal** user logins are part of the standard `C_Login` flow
- the **anonymous** user API key is typically configured in `grep11client.yaml`

### 2. Anonymous, normal, and SO access are meaningfully different

From the reviewed IBM docs:

- **SO user** is responsible for token initialization tasks such as `C_InitToken`
- **normal user** is the practical private-keystore/application user
- **anonymous user** maps to public-keystore access without an explicit application login step

That means unexpected key visibility in the admin panel may be a keystore/user-policy issue, not a wrapper bug.

### 3. Authenticated keystores are optional but operationally important

IBM documents authenticated keystores through `sessionauth` and `tokenspaceIDPassword`.

Practical implication:

- if you enable it, you must configure both public and private keystores consistently
- the password is operator-owned local material
- the repo does not manage or recover that password for you

### 4. Mutual TLS is possible but host-managed

IBM documents optional mutual TLS as a second authentication layer for EP11 connections.

Practical implication:

- if you enable it, the certificate/private-key file paths belong in `grep11client.yaml`
- the admin panel does not manage those certs
- you should treat mTLS as runtime/bootstrap configuration, not app behavior

## Point the core wrapper at IBM HPCS

The practical current integration path is the standard module load against the installed Linux PKCS#11 library.

Example:

```csharp
using System.Text;
using Pkcs11Wrapper;

Environment.SetEnvironmentVariable(
    "EP11CLIENT_CFG",
    "/etc/ep11client/grep11client.yaml");

using Pkcs11Module module = Pkcs11Module.Load("/opt/ibm-hpcs/pkcs11-grep11-amd64.so.2.6.10");
module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

Pkcs11SlotId slotId = module.GetSlotIds(tokenPresentOnly: true)[0];
using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("HPCS_NORMAL_USER_APIKEY")!));
```

Practical guidance:

- set `EP11CLIENT_CFG` explicitly if you do not use `/etc/ep11client/grep11client.yaml`
- keep the module path as host-specific runtime configuration, not a source constant
- treat the login secret as the IBM HPCS user credential material for the chosen PKCS#11 user type
- reacquire objects from the live session rather than assuming cross-session object-handle persistence
- validate against the real IBM module/runtime before relying on uncommon mechanism or attribute behavior

### About `C_Login` credentials here

The repo does not reinterpret IBM credentials; it passes raw bytes into the standard PKCS#11 login flow.

That is exactly the right level of abstraction for HPCS:

- IBM-specific user provisioning happens outside the repo
- the wrapper remains a standard PKCS#11 caller
- operators remain responsible for supplying the right credential material for SO or normal-user flows

## Point the admin panel at IBM HPCS

The current admin path is:

1. run `src/Pkcs11Wrapper.Admin.Web` on a Linux machine/container that already has the IBM client library and config working
2. ensure the runtime can see:
   - the IBM PKCS#11 library
   - `grep11client.yaml`
   - any optional mTLS files
3. if needed, set `EP11CLIENT_CFG` before starting the app
4. open the **Devices** page
5. create or edit a device profile with:
   - **Name**: your operational HPCS label
   - **PKCS#11 Module Path**: the exact IBM library path on that host
   - **Default Token Label**: optional, if your runtime exposes a stable label you want to save
   - **Vendor profile**: **IBM Cloud HPCS / EP11 PKCS#11**
   - **Notes**: optional endpoint/region/runtime breadcrumbs for operators
6. use the built-in **Test** action before relying on the profile

### What is improved in this slice

The admin panel now has a built-in IBM HPCS vendor profile that keeps the following visible to operators:

- Linux-only direct-client expectation for the current repo boundary
- `grep11client.yaml` / `EP11CLIENT_CFG` runtime dependency
- IBM IAM/service-ID-backed login expectations
- GREP11/control-plane tasks staying outside the admin UI

### What not to expect from the admin panel today

Do **not** expect the admin panel to:

- create or initialize IBM Cloud instances for you
- discover instance IDs or EP11 endpoints from IBM Cloud APIs/UI
- create IBM IAM service IDs, access policies, or API keys
- upload or manage mTLS certificates
- act as a GREP11 control plane

The current admin-panel fit is:

- device registration
- live connection testing
- slot/mechanism inspection
- object browsing/detail reads
- standard lab-style diagnostics over IBM's published PKCS#11 surface

## Compatibility notes that matter for wrapper/admin usage

### Standard APIs IBM publicly documents

The reviewed IBM PKCS#11 API reference documents support for standard operations including:

- module lifecycle and info
- slot/token/mechanism enumeration
- `C_InitToken`, `C_InitPIN`, `C_SetPIN`
- session open/close/login/logout
- `C_GetOperationState` / `C_SetOperationState`
- `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_SetAttributeValue`
- encrypt/decrypt, sign/verify, digest, random generation
- `C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`

That is why the current repo can honestly treat IBM HPCS as a stronger standard-PKCS#11 fit than adapter-style cloud targets.

### Important caveats from IBM's own published docs

The reviewed IBM docs also note or imply the following limits:

- `C_WaitForSlotEvent` is not implemented
- `C_SeedRandom` is not implemented
- `C_GetFunctionStatus` / `C_CancelFunction` are legacy non-parallel paths and not implemented
- `C_SetAttributeValue` is documented with a caveat that only Boolean attributes are modifiable
- authenticated-keystore behavior depends on `sessionauth` and IBM-specific keystore password handling

### PKCS#11 v3-only paths remain unclaimed here

This guide does **not** treat the following as established HPCS support claims for the current repo:

- `C_GetInterface*`
- `C_Message*`
- `C_LoginUser`
- `C_SessionCancel`

If future live IBM validation proves them, that can be documented later.

## What can vs cannot be validated locally without real IBM Cloud access

### Can be validated locally in this issue

- docs and support-boundary clarity
- admin-panel vendor profile guidance
- build/test health after the low-risk changes
- that the repo architecture does not require a new abstraction just to represent IBM's direct PKCS#11 path

### Cannot be validated locally in this issue

- live EP11 connectivity
- real `grep11client.yaml` correctness
- IAM service-ID policy correctness
- real SO/normal/anonymous behavior
- `C_InitToken` / keystore initialization against HPCS
- authenticated-keystore flows
- mutual TLS end to end
- real key/object/mechanism semantics against an IBM cloud HSM

## Practical conclusion

For the current repo, the right IBM HPCS support claim is:

- **direct PKCS#11 support path** through IBM's Linux EP11 client library
- **explicitly not** a GREP11/gRPC support claim
- **admin-panel-ready enough** to register/test/browse with honest vendor guidance
- **not yet live-validated** end to end without a real HPCS environment
