# Compatibility matrix

## Validated baseline

| Area | Status | Notes |
| --- | --- | --- |
| OS | Linux | Primary development and validation target |
| Runtime | .NET 10 | Pinned via `global.json` |
| NativeAOT | Supported | Validated by `eng/run-smoke-aot.sh` |
| Reference module | SoftHSM v2 | Default local + CI regression target |
| Optional vendor lane | Supported | Via `eng/run-regression-tests.sh --use-existing-env` and `docs/vendor-regression.md` |

## PKCS#11 surface status

| Capability area | Status | Validation notes |
| --- | --- | --- |
| Core module lifecycle (`C_Initialize`, `C_Finalize`, `C_GetInfo`) | Supported | Covered by API surface and smoke/regression flows |
| Slot / token / mechanism enumeration | Supported | SoftHSM regression coverage |
| Session lifecycle + login/logout | Supported | SoftHSM regression coverage |
| Configurable initialize args / mutex callbacks | Supported | Managed + native API shape coverage |
| Object search / attribute access / create / destroy | Supported | SoftHSM regression coverage |
| Single-part crypto | Supported | SoftHSM regression coverage |
| Multipart crypto + operation state | Supported | SoftHSM regression coverage |
| Recover / combined update flows | Supported | Managed API + runtime coverage |
| Function status / cancel | Capability-gated | Exposed; returns false on modules that report unsupported / non-parallel |
| Interface discovery (`C_GetInterface*`) | Capability-gated | Optional export path; absent on current SoftHSM builds |
| PKCS#11 v3 message APIs (`C_Message*`) | Capability-gated | Exposed through v3 interface list when the module provides it |
| `C_LoginUser` / `C_SessionCancel` | Capability-gated | Routed through the discovered v3 interface |

## Known limitations

- Current automated runtime validation does **not** include a module that exposes PKCS#11 v3 message APIs; those paths are validated by ABI/layout tests and capability-gated behavior today.
- The repository is Linux-first. Other operating systems may work, but are not part of the documented baseline yet.
- Mechanism parameter helpers are intentionally selective; uncommon mechanisms may still require raw parameter bytes.
- Packaging discipline is defined in `docs/release.md`, but external package publication is still a maintainer action rather than an automated CI publish step.
