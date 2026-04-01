# Performance benchmark baseline

- Generated (UTC): 2026-04-01T17:31:13.9622728+00:00
- SDK: 10.0.201
- Runtime: 10.0.5
- Host framework: .NET 10.0.5
- OS: Arch Linux
- Architecture: X64
- PKCS#11 module: `/usr/lib64/softhsm/libsofthsm2.so`
- Benchmark profile: BenchmarkDotNet ShortRun + MemoryDiagnoser

| Category | Suite | Benchmark | Mean | StdDev | Allocated |
| --- | --- | --- | ---: | ---: | ---: |
| Concurrent | SessionAndObjectBenchmarks | GetSessionInfoBurst8Workers | 23.659 μs | 66.811 ns | n/a |
| Concurrent | SessionAndObjectBenchmarks | GetSessionInfoBurst32Workers | 57.605 μs | 907.795 ns | n/a |
| Crypto | CryptoBenchmarks | GenerateRandom32 | 143.994 ns | 0.961 ns | n/a |
| Crypto | CryptoBenchmarks | DigestSha256_1KiB | 770.642 ns | 2.327 ns | n/a |
| Crypto | CryptoBenchmarks | DigestSha256Multipart_1KiB | 882.574 ns | 1.075 ns | n/a |
| Crypto | CryptoBenchmarks | DecryptAesCbcPad_1KiB | 5.487 μs | 2.853 ns | n/a |
| Crypto | CryptoBenchmarks | EncryptAesCbcPad_1KiB | 6.31 μs | 33.703 ns | n/a |
| Crypto | CryptoBenchmarks | VerifySha256RsaPkcs_1KiB | 19.675 μs | 18.88 ns | n/a |
| Crypto | CryptoBenchmarks | SignSha256RsaPkcs_1KiB | 333.909 μs | 39.242 ns | n/a |
| Managed | ManagedTemplateBenchmarks | CreateAesEncryptDecryptTemplate | 20.356 ns | 0.03 ns | n/a |
| Managed | ManagedTemplateBenchmarks | CreateRsaSignVerifyTemplate | 32.441 ns | 0.093 ns | n/a |
| Managed | ManagedTemplateBenchmarks | CreateEcSignVerifyTemplate | 33.007 ns | 0.345 ns | n/a |
| Module | ModuleLifecycleBenchmarks | GetSlotCount | 46.959 ns | 0.417 ns | n/a |
| Module | ModuleLifecycleBenchmarks | EnumerateSlots | 107.307 ns | 0.213 ns | n/a |
| Module | ModuleLifecycleBenchmarks | EnumerateMechanisms | 132.158 ns | 0.338 ns | n/a |
| Module | ModuleLifecycleBenchmarks | GetAesCbcPadMechanismFlags | 1.81 μs | 0.759 ns | n/a |
| Module | ModuleLifecycleBenchmarks | LoadInitializeGetInfoFinalizeDispose | 1.919 μs | 4.016 ns | n/a |
| Object | SessionAndObjectBenchmarks | CreateUpdateDestroyDataObject | 3.634 μs | 13.564 ns | n/a |
| Object | SessionAndObjectBenchmarks | FindAesKeyByLabel | 10.861 μs | 22.677 ns | n/a |
| Object | SessionAndObjectBenchmarks | GenerateDestroyAesKey | 12.494 μs | 38.994 ns | n/a |
| Object | SessionAndObjectBenchmarks | ReadAesKeyLabelAttribute | 15.545 μs | 6.073 ns | n/a |
| Object | SessionAndObjectBenchmarks | GenerateDestroyRsaKeyPair | 23.949 ms | 1.993 ms | n/a |
| Session | SessionAndObjectBenchmarks | OpenReadOnlySessionAndGetInfo | 275.525 ns | 0.534 ns | n/a |
| Session | SessionAndObjectBenchmarks | OpenReadWriteLoginLogoutSession | 292.005 μs | 324.444 ns | n/a |

> Trend note: compare this file across commits or benchmark workflow artifacts to track whether changes improved or regressed the wrapper over time.
