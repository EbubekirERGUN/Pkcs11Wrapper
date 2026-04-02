# Thales Luna extension skeleton

See also:

- `docs/luna-vendor-extension-design.md`
- `docs/luna-integration.md`
- `docs/luna-compatibility-audit.md`

## Purpose

This document captures the **first intentionally narrow Luna extension package skeleton** added to the repository.

It does **not** claim broad `CA_*` coverage.

The goal of this first slice is only to prove that the extension-layer design can be wired safely without polluting the vendor-agnostic core:

- separate Luna managed/native packages exist
- Luna loading is explicit and opt-in
- `CA_GetFunctionList` is resolved against the already-loaded PKCS#11 module
- bootstrap success/failure is capability-gated
- family facades exist, but stay conservative until real Luna API families are implemented

## Packages

The skeleton adds two packages/assemblies:

- `Pkcs11Wrapper.ThalesLuna.Native`
- `Pkcs11Wrapper.ThalesLuna`

They live beside the existing core packages instead of expanding `Pkcs11Wrapper` / `Pkcs11Wrapper.Native` with Luna-only public members.

## What exists today

### Native layer

`Pkcs11Wrapper.ThalesLuna.Native` currently provides:

- explicit `LunaNativeModule.TryLoad(Pkcs11NativeModule, out ...)`
- safe export probing for `CA_GetFunctionList`
- conservative handling for:
  - export missing -> Luna extensions unavailable
  - `CKR_FUNCTION_NOT_SUPPORTED` -> Luna extensions unavailable
  - null function-table pointer after success -> throw as invalid native contract
- bootstrap metadata:
  - `FunctionListVersion`
  - `LunaNativeCapabilities`

### Managed layer

`Pkcs11Wrapper.ThalesLuna` currently provides:

- explicit `LunaExtensions.TryLoad(Pkcs11Module, out ...)`
- a managed `LunaCapabilities` projection
- family placeholders in dedicated namespaces:
  - `HighAvailability`
  - `Cloning`
  - `Policy`
  - `PedMofn`
  - `Containers`
  - `Keys`

Those family placeholders intentionally expose only `IsAvailable` for now.

In this first skeleton they remain `false`, because the repo has not yet implemented or validated any specific Luna `CA_*` family entry points.

## What does not exist yet

This skeleton does **not** yet implement:

- Luna HA operations
- cloning workflows
- PED / MofN flows
- policy/admin operations
- container/key/application-id APIs
- key-specific Luna extension calls
- claims of full or partial `CA_*` runtime support beyond `CA_GetFunctionList` bootstrap

## Example

```csharp
using Pkcs11Wrapper;
using Pkcs11Wrapper.ThalesLuna;

using Pkcs11Module module = Pkcs11Module.Load("/path/to/pkcs11/module");
module.Initialize();

if (LunaExtensions.TryLoad(module, out LunaExtensions? luna))
{
    Console.WriteLine($"Luna extension table version: {luna.FunctionListVersion}");
    Console.WriteLine($"Luna extensions available: {luna.IsAvailable}");
    Console.WriteLine($"HA family ready: {luna.HighAvailability.IsAvailable}");
}
else
{
    Console.WriteLine("Luna CA_* extensions are not available on this module.");
}
```

## Validation strategy

The initial validation lane is intentionally deterministic and conservative:

- managed API surface tests
- native header layout test for the minimal Luna function-table header
- Linux shim-backed runtime tests covering:
  - missing `CA_GetFunctionList` export
  - successful bootstrap
  - `CKR_FUNCTION_NOT_SUPPORTED`
  - invalid null-pointer return

That validates the extension skeleton itself without pretending that a real Luna client/runtime has already passed broader vendor regression.
