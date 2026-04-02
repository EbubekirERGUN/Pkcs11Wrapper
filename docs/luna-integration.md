# Thales Luna integration guide

See also:

- `docs/luna-compatibility-audit.md` for the current standard-vs-extension support boundary
- `docs/vendor-regression.md` for the opt-in Luna-oriented vendor regression profile
- `docs/luna-vendor-extension-design.md` for the future `CA_*` extension-layer plan
- `docs/vendor-audit-integration.md` for the vendor-native audit vs wrapper-telemetry boundary and Luna audit-integration evaluation

## Purpose

This guide turns the completed Luna audit and vendor-regression profile into a practical setup path for the current repository.

It is intentionally conservative:

- it describes how to use **standard PKCS#11 `C_*` flows** with a Luna client/module today
- it shows how to point the **wrapper**, **admin panel**, **smoke sample**, and **vendor regression lane** at a Luna installation
- it keeps **Luna-only `CA_*` APIs** out of scope for the current repo
- it does **not** treat SoftHSM validation depth as proof of Luna-extension support

## What “Luna support” means in this repo today

The current repo is in a good position for **standard Luna PKCS#11 usage** when the scenario stays inside normal `C_*` calls.

That means the current support story is:

### Supported well today

- standard module initialize/finalize and slot/token enumeration
- standard session login/logout and object search flows
- standard encrypt/decrypt, digest, sign/verify, wrap/unwrap, derive, and key-generation paths when the Luna policy/mechanism set exposes them
- explicit Luna library-path usage through `Pkcs11Module.Load(...)`, admin device profiles, or `PKCS11_MODULE_PATH`
- admin-panel inspection and diagnostics through existing standard-centric pages, especially **PKCS#11 Lab**
- the existing vendor regression lane against a prepared Luna environment via the `luna-rsa-aes` profile

### Capability-gated or unverified on Luna

- `C_WaitForSlotEvent`
- `C_GetFunctionStatus` / `C_CancelFunction`
- `C_SignRecover*` / `C_VerifyRecover*`
- `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`
- `C_GetOperationState` / `C_SetOperationState` on Luna keyrings
- PKCS#11 v3 interface discovery (`C_GetInterface*`), message APIs (`C_Message*`), `C_LoginUser`, and `C_SessionCancel` until a real Luna runtime proves them
- mechanisms that require structured vendor-specific parameters not yet modelled by the wrapper

### Not supported today

- `CA_GetFunctionList`
- Luna `CA_*` extension APIs
- Luna-specific HA / cloning / PED / MofN / container / STC / STM / policy-admin workflows
- any claim that the current admin panel or runtime tooling directly covers Luna-only APIs

If you need the deeper rationale behind those boundaries, read `docs/luna-compatibility-audit.md` first.

## Prerequisites

Before wiring Luna into this repo, make sure:

1. the **Luna client is installed on the same host/container** that will run the wrapper, tests, or admin panel
2. the process architecture matches the installed client library architecture
3. you know the target **partition/keyring label** and a working **user PIN**
4. for vendor regression, you already have:
   - one existing AES key usable for encrypt/decrypt
   - one existing RSA keypair usable for `CKM_RSA_PKCS` sign/verify
5. if your Luna deployment depends on additional vendor wrappers/config such as `cklog`, `ckshim`, or Chrystoki config resolution, validate that outside this repo first

## Module path expectations

`Pkcs11Wrapper` uses an **explicit module path**. It does not auto-discover a Luna client installation for you.

Practical implications:

- the host running the code must be able to open the chosen library path directly
- the path must point at the library you intentionally want the wrapper to load
- if the app/admin panel is in a container, the Luna client installation/config must be present inside that container as well
- unlike the SoftHSM sample path, there is **no built-in Luna fallback path** in this repo

### Library naming guidance

The public Thales Luna sample documentation describes the standard client library as:

- `cryptoki.dll` on Windows
- `libCryptoki2.so` on Linux/UNIX

The repo's Luna vendor-profile example uses a 64-bit Linux path placeholder:

- `libCryptoki2_64.so`

So the safe guidance for this repo is:

- use the **exact installed Luna PKCS#11 library path visible on your host**
- on 64-bit Linux, expect a `libCryptoki2*` variant such as the documented example `libCryptoki2_64.so`
- on Windows, expect the Luna PKCS#11 DLL path for your installed client, commonly the `cryptoki.dll` family referenced in the vendor docs

Do **not** hard-code SoftHSM assumptions when switching to Luna.

### Direct cryptoki vs cklog/ckshim

The Thales sample docs note that some deployments intentionally load `cklog` or `ckshim`, which then resolve the underlying cryptoki library through the vendor configuration.

For this repo, that means:

- if you want the wrapper to hit the standard Luna PKCS#11 module directly, point it at the installed `cryptoki` / `libCryptoki2*` library path
- if your deployment intentionally relies on `cklog` or `ckshim`, point the wrapper/admin profile at that library explicitly and make sure the Luna client configuration on that host resolves correctly

Either way, `Pkcs11Wrapper` only knows the path you give it.

## Point the core wrapper at Luna

The simplest integration path is still the direct module load:

```csharp
using Pkcs11Wrapper;

using Pkcs11Module module = Pkcs11Module.Load("/path/to/luna/module");
module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

int slotCount = module.GetSlotCount();
Console.WriteLine($"Discovered {slotCount} slot(s).");
```

Practical guidance:

- keep the module path in app configuration instead of hard-coding it into source
- use the standard `C_*` flow exactly as you would for another vendor module
- treat missing mechanisms or unsupported functions as Luna capability differences unless the env/path/object contract itself is clearly broken
- do **not** assume that a wrapper method automatically means Luna supports the corresponding function at runtime

## Point the admin panel at Luna

The admin panel already supports Luna in the current repo shape, but only through the **standard device-profile path**.

### Recommended setup

1. run `src/Pkcs11Wrapper.Admin.Web` on a machine that already has the Luna client installed
2. open the **Devices** page
3. create or edit a device profile with:
   - **Name**: your operational label for the HSM/partition
   - **PKCS#11 Module Path**: the exact Luna library path on that host
   - **Default Token Label**: the Luna partition/keyring label you expect operators to use most often
   - **Vendor profile**: **Thales Luna / standard PKCS#11** to attach Luna-specific setup reminders without changing the standard PKCS#11 execution model
   - **Notes**: optional client/version/host reminders
4. use the built-in **Test** action before relying on the profile operationally
5. once selected, the Devices / Slots / Keys / PKCS#11 Lab pages will surface Luna-aware setup hints and scope boundaries, but they still intentionally stop short of Luna-only operational APIs

### What to use in the UI

Current best-fit admin surfaces for Luna are:

- **Devices** for explicit module-path management and connection testing
- **Slots / Keys / Objects** for ordinary standard PKCS#11 inspection workflows
- **PKCS#11 Lab** for the most flexible Luna exploration because it accepts:
  - raw mechanism IDs
  - raw attribute IDs
  - controlled standard crypto/object operations using numeric inputs when needed

### What not to expect from the admin panel today

The admin panel does **not** currently add Luna-specific UI for:

- `CA_*` extension calls
- HA control
- cloning
- PED / MofN workflows
- container or keyring administration beyond standard PKCS#11-visible behavior
- STC / STM / policy-admin families

So for Luna, the honest current admin story is:

- standard PKCS#11 device/session/object workflows: yes
- Luna-only admin workflows: no
- raw probing of standard mechanisms/attributes through the lab: yes

## Point the smoke sample at Luna

The smoke sample can be used against Luna only when you provide a real Luna module path and matching token inputs.

Example:

```bash
export PKCS11_MODULE_PATH='/path/to/luna/libCryptoki2_64.so'
export PKCS11_TOKEN_LABEL='your-luna-token-label'
export PKCS11_USER_PIN='your-user-pin'
export PKCS11_FIND_LABEL='existing-aes-label'
export PKCS11_SIGN_FIND_LABEL='existing-rsa-private-label'
dotnet run --project samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release
```

Important caveats:

- the smoke sample has SoftHSM fallback names, not Luna fallback names
- for Luna, set `PKCS11_MODULE_PATH` explicitly
- capability-gated skips on Luna should be read as capability differences, not automatic wrapper failures
- PKCS#11 v3 behavior remains unverified for Luna unless the real runtime exports and passes those paths

See `docs/smoke.md` for the full env contract.

## Point the vendor regression lane at Luna

The repo already includes a Luna-oriented profile for the standard vendor lane.

### Local/manual usage

Start from the checked-in example:

```bash
cp eng/vendor-profiles/luna-rsa-aes.env.example /tmp/luna-rsa-aes.env
# fill in the real Luna path / token label / pins / object labels
set -a
source /tmp/luna-rsa-aes.env
set +a
./eng/run-regression-tests.sh --use-existing-env
```

The key required inputs are:

- `PKCS11_MODULE_PATH`
- `PKCS11_TOKEN_LABEL`
- `PKCS11_USER_PIN`
- `PKCS11_FIND_LABEL`
- `PKCS11_SIGN_FIND_LABEL`

Recommended extras in Luna environments with repeated labels:

- `PKCS11_FIND_ID_HEX`
- `PKCS11_SIGN_FIND_ID_HEX`
- `PKCS11_VERIFY_FIND_LABEL`
- `PKCS11_VERIFY_FIND_ID_HEX`

### What this profile actually proves

The `luna-rsa-aes` profile is still the **existing standard vendor lane**. It proves standard `C_*` PKCS#11 behavior against a prepared Luna environment, including the normal seeded AES/RSA object contract.

It does **not** prove:

- `CA_*` extension availability
- Luna-specific admin/control workflows
- blanket support for every Luna-documented mechanism
- PKCS#11 v3 support on Luna

### Optional provisioning path

If you intentionally want the provisioning/admin regression path as well, set:

```bash
export PKCS11_PROVISIONING_REGRESSION=1
export PKCS11_SO_PIN='your-so-pin'
./eng/run-regression-tests.sh --use-existing-env
```

Only do this when the target slot/policy is appropriate for `InitToken` coverage.

### Optional GitHub Actions vendor lane

The opt-in workflow-dispatch lane can also target Luna, but the runner must still have any required proprietary client/runtime setup.

Set the repository/workflow inputs described in `docs/ci.md`, especially:

- `VENDOR_PKCS11_PROFILE=luna-rsa-aes`
- `VENDOR_PKCS11_MODULE_PATH`
- `VENDOR_PKCS11_TOKEN_LABEL`
- `VENDOR_PKCS11_FIND_LABEL`
- `VENDOR_PKCS11_SIGN_FIND_LABEL`
- secret `VENDOR_PKCS11_USER_PIN`

If the runner also needs a Luna client install or other vendor prerequisites, pass them through the optional workflow dependency-install step documented in `docs/ci.md`.

## Key caveats when using Luna with this repo

### 1. Capability-gated does not automatically mean broken

Luna public docs already mark some standard PKCS#11 calls as unsupported, and some behavior varies by partition/keyring or token policy.

So if a test or manual experiment shows one of those paths as unavailable, first ask:

- is this a documented Luna capability boundary?
- is this keyring-vs-partition behavior?
- is this token policy/mechanism exposure rather than wrapper breakage?

### 2. Keyring/partition differences matter

The most important current repo-level example is operation-state support:

- safer expectation on Luna partitions
- capability-gated on Luna keyrings

Do not document or automate Luna behavior as though all token types expose the same surface.

### 3. Raw numeric mechanism/attribute support helps, but helpers are selective

The wrapper can represent many mechanism and attribute IDs numerically, and the admin lab can accept raw numeric input.

That is useful for Luna, but it does **not** guarantee that every vendor-specific parameter structure already has first-class marshalling support.

### 4. PKCS#11 v3 on Luna is still unverified here

The repo supports PKCS#11 v3 in general, but the completed Luna audit did not verify public Luna runtime support for:

- `C_GetInterface*`
- `C_Message*`
- `C_LoginUser`
- `C_SessionCancel`

Treat those as unverified for Luna until a real Luna runtime is validated explicitly.

### 5. `CA_*` remains out of scope

This is the most important expectation-setting point.

Current Luna integration in this repo means:

- **standard `C_*` Luna usage**: yes
- **Luna extension-table loading and `CA_*` workflows**: no

If deeper Luna support becomes a product goal later, the design direction is already documented in `docs/luna-vendor-extension-design.md`.

## Related docs

- `docs/luna-compatibility-audit.md`
- `docs/vendor-regression.md`
- `docs/luna-vendor-extension-design.md`
- `docs/ci.md`
- `docs/smoke.md`
- `eng/vendor-profiles/luna-rsa-aes.env.example`
