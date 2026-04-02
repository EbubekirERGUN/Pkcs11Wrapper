# Performance benchmark baseline

- Generated (UTC): 2026-04-02T10:17:27.1621650+00:00
- SDK: 10.0.201
- Runtime: 10.0.5
- Host framework: .NET 10.0.5
- OS: Arch Linux
- Architecture: X64
- PKCS#11 module: `/usr/lib64/softhsm/libsofthsm2.so`
- Benchmark profile: BenchmarkDotNet ShortRun + MemoryDiagnoser

| Category | Suite | Benchmark | Mean | StdDev | Allocated | Gen0 | Gen1 | Gen2 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Concurrent | SessionAndObjectBenchmarks | GetSessionInfoBurst8Workers | 30.293 μs | 79.9 ns | 3,693 B | 2 | 0 | 0 |
| Concurrent | SessionAndObjectBenchmarks | GetSessionInfoBurst32Workers | 77.878 μs | 3.248 μs | 5,326 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | GenerateRandom32 | 149.094 ns | 0.215 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | DigestSha256_1KiB | 831.327 ns | 0.595 ns | 40 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | DigestSha256Multipart_1KiB | 919.252 ns | 0.781 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | DecryptAesCbcPad_1KiB | 5.471 μs | 5.557 ns | 40 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | EncryptAesCbcPad_1KiB | 6.352 μs | 19.092 ns | 40 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | VerifySha256RsaPkcs_1KiB | 19.607 μs | 11.631 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | SignSha256RsaPkcs_1KiB | 334.127 μs | 137.104 ns | 40 B | 0 | 0 | 0 |
| Managed | ManagedTemplateBenchmarks | CreateAesEncryptDecryptTemplate | 19.968 ns | 0.04 ns | 544 B | 363 | 0 | 0 |
| Managed | ManagedTemplateBenchmarks | CreateRsaSignVerifyTemplate | 32.506 ns | 0.101 ns | 880 B | 294 | 0 | 0 |
| Managed | ManagedTemplateBenchmarks | CreateEcSignVerifyTemplate | 32.897 ns | 0.046 ns | 888 B | 296 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | GetSlotCount | 49.592 ns | 0.25 ns | 0 B | 0 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | EnumerateSlots | 110.343 ns | 1.11 ns | 0 B | 0 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | EnumerateMechanisms | 152.754 ns | 0.773 ns | 0 B | 0 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | GetAesCbcPadMechanismFlags | 1.812 μs | 2.595 ns | 0 B | 0 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | LoadInitializeGetInfoFinalizeDispose | 1.934 μs | 6.369 ns | 496 B | 2 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | CreateUpdateDestroyDataObject | 3.878 μs | 3.875 ns | 784 B | 2 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | GenerateDestroyAesKey | 13.191 μs | 603.797 ns | 312 B | 0 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | ReadAesKeyLabelAttribute | 15.623 μs | 10.098 ns | 32 B | 0 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | FindAesKeyByLabel | 50.886 μs | 62.674 ns | 0 B | 0 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | GenerateDestroyRsaKeyPair | 25.145 ms | 1.114 ms | 1,226 B | 0 | 0 | 0 |
| Object, Scalability | SessionAndObjectBenchmarks | BrowseFirstDataObjectPage64Of256 | 49.451 μs | 133.273 ns | 176 B | 0 | 0 | 0 |
| Session | SessionAndObjectBenchmarks | OpenReadOnlySessionAndGetInfo | 8.036 μs | 8.267 ns | 56 B | 0 | 0 | 0 |
| Session | SessionAndObjectBenchmarks | OpenReadWriteLoginLogoutSession | 281.982 μs | 113.673 ns | 56 B | 0 | 0 | 0 |

> Trend note: compare this file across commits or benchmark workflow artifacts to track whether changes improved or regressed the wrapper over time.
