# Pkcs11Wrapper

Modern .NET 10 PKCS#11 wrapper focused on explicit APIs, NativeAOT-aware interop, and practical validation on Linux and Windows.

## Packages

- `Pkcs11Wrapper` — high-level managed wrapper over a PKCS#11 / Cryptoki module
- `Pkcs11Wrapper.Native` — lower-level NativeAOT-friendly interop layer used by the main package

## Install

```bash
dotnet add package Pkcs11Wrapper
```

Low-level interop package:

```bash
dotnet add package Pkcs11Wrapper.Native
```

## Minimal example

```csharp
using Pkcs11Wrapper;

using Pkcs11Module module = Pkcs11Module.Load("/path/to/pkcs11/module");
module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

int slotCount = module.GetSlotCount();
Console.WriteLine($"Discovered {slotCount} slot(s).");
```

## Validation highlights

- fixture-backed SoftHSM regression suite
- Linux NativeAOT smoke validation
- Windows runtime validation with SoftHSM-for-Windows
- BenchmarkDotNet baseline and CI reporting

## Documentation

- Repository: https://github.com/EbubekirERGUN/Pkcs11Wrapper
- Development guide: https://github.com/EbubekirERGUN/Pkcs11Wrapper/blob/main/docs/development.md
- Smoke sample guide: https://github.com/EbubekirERGUN/Pkcs11Wrapper/blob/main/docs/smoke.md
- CI / validation guide: https://github.com/EbubekirERGUN/Pkcs11Wrapper/blob/main/docs/ci.md
- Release / packaging guide: https://github.com/EbubekirERGUN/Pkcs11Wrapper/blob/main/docs/release.md

## Notes

- Runtime behavior still depends on the target PKCS#11 module / token / HSM policy.
- PKCS#11 v3 support is capability-gated based on what the module actually exports.
- SourceLink-enabled symbols are produced for package debugging scenarios.
