# IBM Cloud Hyper Protect Crypto Services compatibility audit

See also:

- `docs/ibm-cloud-hpcs-integration.md` for the practical wrapper/admin-panel setup path
- `docs/compatibility-matrix.md` for the repo-wide support summary
- `docs/vendor-regression.md` for the current vendor-lane boundary

## Scope

This document records the research for issue #69 and answers a narrow question:

> How well does IBM Cloud Hyper Protect Crypto Services (HPCS) fit the current `Pkcs11Wrapper` + admin-panel architecture?

The answer is **better than an adapter-style cloud PKCS#11 story like Google kmsp11, but still with important boundaries**.

The practical fit is:

- **direct PKCS#11** for IBM's published **EP11 PKCS#11 client library** on Linux
- **not** a blanket "all IBM HPCS integration styles are the same" story
- **not** a reason to pretend that the separate **GREP11 gRPC** path is already covered by the current PKCS#11 wrapper/admin boundary

## IBM public references reviewed

The research for this issue was based on IBM public material that, at the time of review, stated the following:

- IBM Cloud docs: **Performing cryptographic operations with the PKCS #11 API**
  - documents HPCS PKCS#11 setup through a local client library plus `grep11client.yaml`
  - documents EP11 endpoint URL/port, IAM auth, optional mutual TLS, keystore UUIDs, and `EP11CLIENT_CFG`
- IBM Cloud docs: **Performing cryptographic operations with the GREP11 API**
  - documents a separate GREP11 API path over gRPC
- IBM Cloud docs: **Enabling the second layer of authentication for EP11 connections**
  - documents optional mutual TLS for EP11 connections
- IBM Cloud docs: **PKCS#11 API reference**
  - publishes a PKCS#11 v2.40-style implemented-function table and supported attribute/mechanism documentation
- IBM-Cloud GitHub repo: **`IBM-Cloud/hpcs-pkcs11`**
  - documents packaging and release assets for the HPCS PKCS#11 client
  - states the PKCS#11 library is currently supported only on **Linux (GLIBC distros only)** for **amd64** and **s390x**

## Repository areas reviewed

- `src/Pkcs11Wrapper*`
- `src/Pkcs11Wrapper.Admin.*`
- `tests/*`
- existing cloud-vendor docs for AWS, Google, and OCI

## Executive summary

### 1. IBM HPCS has a real direct PKCS#11 fit for this repo

Unlike Google Cloud HSM's reviewed path, which is an indirect PKCS#11 adapter (`kmsp11`) over a different control plane, IBM HPCS publishes a **direct PKCS#11 client library** that applications load locally.

That matches the current repo's core shape:

- explicit module path
- standard `C_*` entry points
- standard slot/session/object/mechanism workflows
- generic admin-panel diagnostics and object-management surfaces

### 2. IBM HPCS also has a separate GREP11 path, and that is a different abstraction boundary

IBM documents both:

- a **PKCS#11 library** path
- a **GREP11 API** path

Those should not be conflated.

For this repo today:

- the **PKCS#11 library** is the relevant fit
- the **GREP11 gRPC API** is a separate client/integration surface and should stay out of current wrapper/admin claims unless the repo adds a different abstraction layer later

### 3. IBM's published PKCS#11 surface is broad enough that the generic admin panel is a plausible fit

IBM's PKCS#11 API reference publicly documents support for many standard functions that matter to the current repo, including:

- `C_Initialize`, `C_Finalize`, `C_GetInfo`
- slot/token/mechanism enumeration
- `C_InitToken`, `C_InitPIN`, `C_SetPIN`
- `C_OpenSession`, `C_Login`, `C_Logout`
- `C_GetOperationState`, `C_SetOperationState`
- `C_CreateObject`, `C_CopyObject`, `C_SetAttributeValue` (with caveats)
- `C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`

That is materially broader than the reviewed Google kmsp11 story and closer to the kind of standard-token contract this repo already expects.

### 4. The direct path is Linux-first, and current reviewed public packaging does not justify a Windows direct-PKCS#11 claim

IBM's public client repo states that the HPCS PKCS#11 library is currently supported only on **Linux (GLIBC distros only)** for **amd64** and **s390x**.

So the current conservative repo stance should be:

- **Linux**: direct IBM HPCS PKCS#11 support path
- **Windows**: no current reviewed public direct PKCS#11 client packaging claim for this repo boundary

That does not mean IBM has no Windows-related tooling anywhere; it means the reviewed public direct client packaging for the current repo boundary is Linux-only.

### 5. Honest end-to-end validation still requires a real IBM Cloud instance

The repo can now document IBM well and improve admin-panel readiness without pretending it validated:

- live EP11 endpoints
- service initialization/bootstrap
- IAM service ID/user creation
- anonymous/normal/SO access-policy behavior
- authenticated keystores
- mutual TLS
- real HPCS key/object semantics

So the correct first slice is **docs + admin guidance + tests**, not a fake smoke lane.

## Compatibility assessment

## Standard wrapper fit

| Area | Current fit | Notes |
| --- | --- | --- |
| Module loading via explicit library path | Good fit | IBM publishes a host-local PKCS#11 library that the wrapper can load directly. |
| Standard `C_*` entry-point usage | Good fit | IBM publishes a broad PKCS#11 function table rather than an adapter-only subset. |
| Slot / token / mechanism inspection | Good fit | IBM documents standard slot/token/mechanism APIs. |
| Session + login/logout flows | Good fit | IBM documents `C_OpenSession`, `C_Login`, `C_Logout`, plus SO/normal/anonymous user handling. |
| Object discovery / reads | Good fit | Standard `C_FindObjects*` + `C_GetAttributeValue` are documented. |
| Object create/copy/edit/destroy | Partial but promising | IBM documents `C_CreateObject`, `C_CopyObject`, `C_SetAttributeValue`, and destroy paths, but `C_SetAttributeValue` is documented with a caveat that only Boolean attributes are modifiable. |
| Key generation / wrap / unwrap / derive | Good fit | IBM documents these standard key-management functions. |
| Provisioning/admin token functions | Plausible fit | IBM documents `C_InitToken`, `C_InitPIN`, and `C_SetPIN`, which is unusually strong for a cloud-backed PKCS#11 target. Live validation is still required. |
| Operation-state flows | Plausible fit | IBM documents `C_GetOperationState` and `C_SetOperationState`. |
| PKCS#11 v3-only interfaces/messages | Unclaimed / unvalidated | No current IBM HPCS documentation reviewed for this issue was used to justify `C_GetInterface*`, `C_Message*`, `C_LoginUser`, or `C_SessionCancel` claims. |

## IBM-documented unsupported / capability-gated areas

From the reviewed IBM PKCS#11 function table:

- `C_WaitForSlotEvent` is documented as **not implemented**
- `C_SeedRandom` is documented as **not implemented**
- `C_GetFunctionStatus` is documented as **not implemented** / legacy non-parallel
- `C_CancelFunction` is documented as **not implemented** / legacy non-parallel

These map cleanly to the repo's existing capability-gated mindset.

## IBM-specific operational contract that matters

### Client/config model

IBM's direct PKCS#11 path requires more than just a shared library:

- the PKCS#11 client library (`pkcs11-grep11-*.so.<version>`)
- a `grep11client.yaml` configuration file
- EP11 endpoint URL + port
- IAM-backed auth configuration
- public/private keystore UUIDs
- optional session-auth keystore password configuration
- optional mutual TLS certificate/key paths

The config file normally lives in `/etc/ep11client`, or the host can point to it through `EP11CLIENT_CFG`.

That fits the current repo **operationally**, but it is a host-runtime concern, not something the wrapper/admin panel currently provisions for the user.

### User/auth model

IBM's PKCS#11 docs describe three relevant user concepts:

- **SO user**
- **normal user**
- **anonymous user**

The practical repo implication is that IBM HPCS is not using a generic local token PIN story:

- the **anonymous** user API key is configured in `grep11client.yaml`
- **SO** and **normal** user credentials are tied to IBM IAM service ID API keys and are passed through the standard PKCS#11 login flow
- keystore access and policy are IBM-control-plane concerns that must already be configured outside this repo

### Optional authenticated keystores

IBM documents authenticated keystores via `sessionauth` / `tokenspaceIDPassword`.

Important practical detail:

- if enabled, the password must be configured for both private and public keystores
- IBM documents the password length as **6-8 characters**
- password custody stays with the operator, not IBM HPCS

This is compatible with the wrapper's raw PKCS#11 boundary, but it is definitely an operator/runtime concern rather than a repo-managed abstraction today.

### Optional mutual TLS

IBM documents optional mutual TLS for EP11 connections.

That means the repo should describe mTLS like this:

- possible and documented
- host/runtime configured
- not managed by the admin panel
- not locally validated in this issue

## What already lines up well with the current repo

The following existing repo design choices age well for IBM HPCS:

- explicit module-path loading instead of vendor-specific hidden discovery
- strong standard `C_*` surface coverage in the wrapper
- admin-panel emphasis on live device testing, slot inspection, key browsing, and operator-visible boundaries
- capability-gated treatment of legacy/non-parallel functions
- vendor-profile guidance in the admin panel for environment/setup caveats

In other words, IBM HPCS is a case where the current repo architecture is already reasonably shaped for the direct PKCS#11 path.

## What does not fit the current repo boundary

### GREP11 gRPC integration

IBM's GREP11 API is real, but it is **not the same surface** as loading a PKCS#11 library.

Supporting GREP11 properly would likely require:

- a separate client abstraction
- separate auth/bootstrap handling
- a different test story
- separate admin UX language

So the repo should keep GREP11 out of the current support claim.

### IBM control-plane/bootstrap tasks

The current repo does not:

- create HPCS instances
- initialize an instance
- create IAM service IDs or API keys
- fetch endpoint URLs or instance IDs from IBM Cloud APIs/UI
- manage uploaded client certs for mTLS

Those belong to IBM Cloud setup flows, not this repo.

### Windows direct client path

Because the reviewed public packaging guidance was Linux-only, the repo should avoid implying that the current direct PKCS#11 wrapper/admin path is ready on Windows for HPCS.

## What can vs cannot be validated locally without real IBM Cloud access

### Can be validated locally in this issue

- repo documentation quality and boundary clarity
- admin-panel vendor profile guidance and test coverage
- solution build/test integrity after the low-risk code additions
- that the repo can represent IBM HPCS as a direct PKCS#11 target without changing the core wrapper model

### Cannot be validated locally in this issue

- real module loading against IBM's library
- real EP11 network reachability
- `grep11client.yaml` correctness against a live instance
- SO/normal/anonymous access-policy behavior
- `C_InitToken` / authenticated keystore behavior against HPCS
- mutual TLS end to end
- real mechanism/key/object behavior in IBM Cloud

## Practical conclusion

IBM Cloud HPCS is a **real direct PKCS#11 target** for `Pkcs11Wrapper` **when the integration uses IBM's EP11 PKCS#11 client on Linux**.

That makes it a stronger fit for the current repo than indirect adapter-style cloud PKCS#11 stories.

But the right claim is still a conservative one:

- **supported path today**: documented direct Linux PKCS#11 integration + admin-panel vendor guidance
- **explicitly out of scope today**: GREP11 gRPC, IBM control-plane/bootstrap automation, and Windows direct-PKCS#11 claims
- **still required for deeper confidence**: real IBM Cloud validation against a live HPCS instance
