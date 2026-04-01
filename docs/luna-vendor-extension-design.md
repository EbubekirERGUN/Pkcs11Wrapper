# Thales Luna vendor-extension layer design

See also:

- `docs/luna-compatibility-audit.md` for the current standard-vs-extension support boundary
- `docs/vendor-regression.md` for the existing standard PKCS#11 vendor validation lane

## Summary

The repository should support **Thales Luna-specific `CA_*` APIs only through an opt-in vendor extension layer**, not by expanding the vendor-agnostic core wrapper.

That means:

- `Pkcs11Wrapper` and `Pkcs11Wrapper.Native` stay focused on standard PKCS#11 `C_*` / `CK_*`
- Luna-only function tables, constants, structs, and workflows live in a dedicated Thales/Luna layer
- loading of Luna extensions is **explicit and capability-gated** through `CA_GetFunctionList`
- no standard core API should silently redirect to a Luna replacement such as `CA_WaitForSlotEvent` or `CA_SessionCancel`

This keeps the current architecture honest: the core wrapper remains portable, while Luna support can grow in a separate package without polluting the base API for every other HSM.

## Why this shape fits the current repo

The completed audit already established the key boundary:

- standard Luna `C_*` usage fits the current wrapper reasonably well
- Luna-specific `CA_*` extensions are not loaded or projected today
- the repo already separates managed wrapper concerns (`src/Pkcs11Wrapper`) from low-level interop concerns (`src/Pkcs11Wrapper.Native`)
- the repo already treats optional PKCS#11 surfaces as **capability-gated** (`C_GetInterface*`, `C_Message*`, `C_LoginUser`, `C_SessionCancel`)

The public Luna sample documentation also shows the same conceptual split:

- standard calls are loaded through `C_GetFunctionList`
- Luna extensions are loaded separately through `CA_GetFunctionList`
- the Luna extension function table is described as containing **some but not all** Luna extension functions

That is a strong signal that the Luna layer should be modeled as a **separate optional binding surface**, not as an unconditional expansion of the standard core.

## Design goals

1. Keep the core wrapper vendor-agnostic.
2. Make Luna extension usage explicit instead of implicit.
3. Reuse existing `Pkcs11Module` / `Pkcs11Session` lifecycle guarantees where possible.
4. Preserve the repo's NativeAOT-friendly, low-allocation, capability-gated style.
5. Allow future Luna feature slices to ship incrementally by API family instead of attempting ~300 `CA_*` functions at once.

## Non-goals

This design does **not** try to:

- implement any `CA_*` APIs in this issue
- promise blanket coverage for the full Luna extension catalog
- create a generic cross-vendor plugin system for every PKCS#11 vendor
- hide Luna-only concepts behind fake vendor-neutral abstractions
- add Luna-specific admin-panel UI before a stable managed Luna extension API exists
- treat current SoftHSM validation as proof of Luna extension compatibility

## Recommended package and namespace structure

The cleanest shape is to mirror the repo's current managed/native split.

| Layer | Package / assembly | Primary namespace(s) | Responsibility |
| --- | --- | --- | --- |
| Standard managed core | `Pkcs11Wrapper` | `Pkcs11Wrapper` | Standard PKCS#11 module/session/object/crypto API only |
| Standard native core | `Pkcs11Wrapper.Native` | `Pkcs11Wrapper.Native`, `Pkcs11Wrapper.Native.Interop` | Standard `CK_*` structs, `CK_FUNCTION_LIST`, native loading, core lifecycle |
| Luna native extension | `Pkcs11Wrapper.ThalesLuna.Native` | `Pkcs11Wrapper.ThalesLuna.Native`, `Pkcs11Wrapper.ThalesLuna.Native.Interop` | `CA_GetFunctionList`, Luna-only structs/constants/function tables, low-level invocation |
| Luna managed extension | `Pkcs11Wrapper.ThalesLuna` | `Pkcs11Wrapper.ThalesLuna` plus family namespaces | Managed Luna-only API over existing `Pkcs11Module` / `Pkcs11Session` |

### Public namespace guidance

Recommended public namespaces inside `Pkcs11Wrapper.ThalesLuna`:

- `Pkcs11Wrapper.ThalesLuna`
- `Pkcs11Wrapper.ThalesLuna.HighAvailability`
- `Pkcs11Wrapper.ThalesLuna.Cloning`
- `Pkcs11Wrapper.ThalesLuna.Policy`
- `Pkcs11Wrapper.ThalesLuna.PedMofn`
- `Pkcs11Wrapper.ThalesLuna.Containers`
- `Pkcs11Wrapper.ThalesLuna.Keys`

The exact family names can still be refined when implementation starts, but the important decision is that **family-specific Luna APIs do not sit in the root `Pkcs11Wrapper` namespace**.

## Boundary rules: what stays in core vs Luna layer

### Core stays responsible for

- standard `C_*` and `CK_*` PKCS#11 types and functions
- `Pkcs11Module`, `Pkcs11Session`, `Pkcs11SlotId`, `Pkcs11ObjectHandle`, `Pkcs11Mechanism`, and standard attribute/template handling
- capability-gated standard surfaces such as `C_GetInterface*` and `C_Message*`
- vendor-neutral error taxonomy and raw `CK_RV` preservation
- standard vendor regression against a prepared Luna environment when the scenario stays inside `C_*`

### Luna layer becomes responsible for

- resolving `CA_GetFunctionList`
- Luna-only function-table interop (`CK_SFNT_CA_FUNCTION_LIST` or equivalent documented Luna table definitions)
- Luna-only constants, structs, enums, and helper DTOs
- Luna-only workflows such as HA, cloning, PED/MofN, container/application-id management, policy/admin operations, and other `CA_*` families
- Luna-specific capability discovery and family availability metadata

### Explicitly rejected boundary choices

#### Do not add `CA_*` members to `Pkcs11Module` or `Pkcs11Session`

That would immediately leak Luna concepts into the vendor-agnostic core and would make every future vendor-extension request harder to contain.

#### Do not silently swap standard calls for Luna replacements

Examples:

- `Pkcs11Module.WaitForSlotEvent()` must remain the standard `C_WaitForSlotEvent` path
- `Pkcs11Session.SessionCancel()` must remain the standard `C_SessionCancel` path

If a caller wants `CA_WaitForSlotEvent` or `CA_SessionCancel`, they should opt into the Luna package and call the Luna API explicitly.

#### Do not expose raw native handles publicly just to support Luna

The extension layer should integrate with existing session/module objects through narrow internal seams, not by weakening the public encapsulation of `Pkcs11Module` and `Pkcs11Session`.

## Recommended managed API shape

The entry point should be an explicit extension loader on top of an already-loaded standard module.

Illustrative shape:

```csharp
using Pkcs11Wrapper;
using Pkcs11Wrapper.ThalesLuna;

using Pkcs11Module module = Pkcs11Module.Load(path);
module.Initialize();

if (LunaExtensions.TryLoad(module, out LunaExtensions luna))
{
    if (luna.HighAvailability.IsAvailable)
    {
        // future Luna-only calls live here
    }
}
```

Recommended managed entry types:

- `LunaExtensions` - top-level opt-in extension root for one loaded module
- family-scoped facades hanging off that root, for example:
  - `LunaHighAvailabilityExtensions`
  - `LunaCloningExtensions`
  - `LunaPolicyExtensions`
  - `LunaPedMofnExtensions`
  - `LunaContainerExtensions`
  - `LunaKeyExtensions`

### Why family facades instead of one giant `CA_*` class?

Because the public Luna catalog is large and uneven:

- some functions are firmware-dependent
- some are admin-only
- some are session-based while others are slot-based
- some appear to be convenience replacements for standard calls, while others are entirely Luna-specific feature areas

A single flat class with hundreds of methods would be difficult to version, test, document, and review. Family-scoped facades let the repo ship support incrementally and keep each slice understandable.

## Loading and binding strategy

### 1. Use the same native library instance as the core module

The Luna layer should bind against the **same already-loaded native module** that `Pkcs11Module` uses.

It should **not** independently call `NativeLibrary.Load(path)` on the same library as its normal path because that introduces avoidable ambiguity around:

- initialization ownership
- finalize/dispose ownership
- duplicate load behavior on different platforms
- future wrapper assumptions about shared lifecycle state

### 2. Add a narrow internal export-resolution seam in the core

The core repo should expose only a **minimal internal seam** needed by the Luna extension package, for example via `InternalsVisibleTo` from:

- `Pkcs11Wrapper.Native` to `Pkcs11Wrapper.ThalesLuna.Native`
- `Pkcs11Wrapper` to `Pkcs11Wrapper.ThalesLuna`

That seam should allow the Luna layer to:

- resolve an optional export such as `CA_GetFunctionList` from the already-loaded module
- invoke Luna calls with validated session/module state
- reuse existing session invalidation checks instead of bypassing them

This is preferable to adding public `Handle`, `TryGetExport`, or raw-session-pointer APIs to the vendor-neutral core.

### 3. Load `CA_GetFunctionList` lazily and explicitly

Recommended flow for `LunaExtensions.TryLoad(module, out luna)`:

1. confirm the standard `Pkcs11Module` is still alive
2. resolve the `CA_GetFunctionList` export from the underlying library
3. if the export is absent, return `false`
4. call `CA_GetFunctionList` once and cache the returned Luna function table pointer
5. inspect which family entry points are non-null and publish that as capability metadata
6. create family facades over the cached table

If the export is absent or function-table retrieval fails with a not-supported style result, the Luna layer should report **not available**, not fabricate a partial success.

### 4. Keep lifecycle ownership in the standard module

`LunaExtensions` should **not** own `C_Initialize`, `C_Finalize`, or module disposal.

The lifecycle contract should be:

- `Pkcs11Module` owns native library lifetime and standard PKCS#11 initialization/finalization
- `LunaExtensions` is a dependent view over the same loaded module
- disposing the Luna object should only dispose its own managed caches/resources, not finalize the PKCS#11 module
- Luna calls fail once the owning `Pkcs11Module` or `Pkcs11Session` becomes invalid

### 5. Reuse core wrapper types wherever the underlying concept is still standard

Use existing core types for shared concepts whenever possible:

- `Pkcs11Module`
- `Pkcs11Session`
- `Pkcs11SlotId`
- `Pkcs11ObjectHandle`
- `Pkcs11Mechanism`
- `Pkcs11ObjectAttribute`

Add new public Luna-only DTOs only when the parameter/result truly has vendor-specific meaning.

That keeps the Luna package from duplicating the core object model.

### 6. Preserve raw return values and capability behavior

The Luna layer should follow the repo's existing behavior philosophy:

- preserve the raw numeric return/result codes from the Luna library
- map known capability-absent or not-supported cases explicitly
- avoid pretending that Luna-only failures belong to the standard PKCS#11 taxonomy when they do not

Where Luna introduces documented vendor-only return codes or status payloads, the managed API should expose them directly rather than normalizing them into vague booleans.

## Testing and validation strategy

A Luna extension layer should follow the same pattern the repo already uses for PKCS#11 v3 support: validate deterministic binding behavior locally/CI, then keep real vendor runtime validation opt-in.

### 1. Shape and layout tests

Add a dedicated test project when implementation starts, for example:

- `tests/Pkcs11Wrapper.ThalesLuna.Tests`

This should cover:

- managed public API shape for the Luna package
- native struct layout for the Luna function table and any supported Luna structs
- null-pointer / optional-function / missing-export behavior
- raw return-code preservation and capability reporting

### 2. Deterministic Luna-extension shim tests

The repo should add a small deterministic native shim, similar in spirit to the current PKCS#11 v3 shim, that exports:

- `C_GetFunctionList`
- `CA_GetFunctionList`
- a very small, intentionally chosen subset of `CA_*` functions for the first implemented family

This gives the repo a way to validate:

- export discovery
- function-table marshalling
- session-handle pass-through
- buffer-probe patterns
- capability-gated missing-function behavior
- NativeAOT/runtime compatibility of the managed Luna layer

without requiring the proprietary Luna client in baseline CI.

### 3. Manual / opt-in real Luna validation

Real Luna validation should stay opt-in and manual or workflow-dispatch based.

When the first real `CA_*` family is implemented, add a documented extension-specific validation path that is clearly separate from the existing standard vendor lane.

That future lane should:

- require a prepared Luna environment
- remain out of baseline CI
- state exactly which `CA_*` families it validates
- record tested Luna client/firmware versions in docs or job summaries

### 4. Validation order for future implementation issues

For actual Luna implementation slices, the expected validation bar should be:

1. API/layout tests
2. deterministic shim runtime tests
3. release build of the solution
4. optional real Luna manual verification when hardware/client access exists

## Versioning and compatibility risks

### 1. The Luna extension catalog is firmware/client-version sensitive

The public docs explicitly mark some `CA_*` functions as requiring minimum firmware/client versions.

So the extension layer must assume:

- some functions exist only on certain Luna releases
- some functions may be present only for certain deployment styles or roles
- support claims need to be per family/function, not blanket “Luna supported” statements

### 2. The function table is vendor-defined, not PKCS#11-standardized

Unlike the standard `CK_FUNCTION_LIST`, the Luna extension table is vendor-defined and documented separately.

That creates extra risk around:

- struct layout drift between Luna releases
- deprecated functions that remain in older docs or clients
- partial availability where the table exposes only some functions

The implementation should therefore bind conservatively:

- start with a small supported subset
- validate the exact interop definitions against a shim and at least one real Luna runtime before expanding
- treat unknown or undocumented layout changes as fail-closed, not as “probably compatible”

### 3. Core and Luna package versions should ship together

Even though the Luna layer is optional, it will rely on internal seams from the core projects.

So the safest release model is:

- keep `Pkcs11Wrapper`, `Pkcs11Wrapper.Native`, `Pkcs11Wrapper.ThalesLuna`, and `Pkcs11Wrapper.ThalesLuna.Native` in the same repo release train
- version them together using the repo's normal SemVer cadence
- document Luna validation status separately from package version numbers

In practice that means:

- additive Luna family support -> minor release
- bug fixes/docs/validation-only changes -> patch release
- breaking changes to Luna managed API or native binding assumptions -> major release

### 4. Do not infer support from standard Luna success

A successful standard Luna run through `docs/vendor-regression.md` proves only the standard `C_*` contract being exercised.

It does **not** prove:

- `CA_GetFunctionList` availability
- Luna extension table compatibility
- any specific HA/cloning/PED/container/admin feature family

Those claims should remain separate in docs, tests, and release notes.

## What should remain out of scope for the first implementation wave

Even after implementation starts, the first Luna extension issues should stay narrow.

Out of scope for the first wave:

- covering the full public `CA_*` catalog
- adding Luna-specific UI/workflows to the admin panel
- trying to unify Luna-only concepts into vendor-neutral core abstractions
- promising support for undocumented or runtime-unverified Luna functions
- automatically probing and invoking Luna replacements from existing standard wrapper methods
- treating proprietary Luna client installation as a baseline CI dependency

A better first implementation slice would be one small, well-documented family with deterministic shim coverage and an optional real-Luna validation note.

## Recommended follow-up implementation order

When the repo is ready to implement actual Luna APIs, the safest order is:

1. add the internal export/session seams needed by the extension package without changing the public core API
2. add the Luna native package skeleton and function-table binding
3. add one small managed Luna family facade with deterministic shim tests
4. document real Luna manual validation for that single family
5. expand family-by-family only after the loader, lifecycle, and versioning model prove stable

## Final recommendation

The repo should treat Thales Luna extensions as a **separate, explicit, opt-in vendor package stack**:

- core packages stay standard-only
- Luna packages own `CA_*`
- binding happens lazily through `CA_GetFunctionList`
- lifecycle ownership stays with `Pkcs11Module`
- capability gating, deterministic shim testing, and conservative version claims remain mandatory

That is the cleanest path to deeper Luna support without damaging the current wrapper architecture.