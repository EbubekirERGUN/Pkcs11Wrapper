# Performance benchmark baseline

- Generated (UTC): 2026-04-01T17:31:13.9622728+00:00
- SDK: 10.0.201
- Runtime: 10.0.5
- Host framework: .NET 10.0.5
- OS: Arch Linux
- Architecture: X64
- PKCS#11 module: `/usr/lib64/softhsm/libsofthsm2.so`
- Benchmark profile: BenchmarkDotNet ShortRun + MemoryDiagnoser

| Category | Suite | Benchmark | Mean | StdDev | Allocated | Gen0 | Gen1 | Gen2 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Concurrent | SessionAndObjectBenchmarks | GetSessionInfoBurst8Workers | 23.659 μs | 66.811 ns | 0 B | 0 | 0 | 0 |
| Concurrent | SessionAndObjectBenchmarks | GetSessionInfoBurst32Workers | 57.605 μs | 907.795 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | GenerateRandom32 | 149.717 ns | 0.138 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | DigestSha256_1KiB | 780.351 ns | 2.345 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | DigestSha256Multipart_1KiB | 1.061 μs | 47.917 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | DecryptAesCbcPad_1KiB | 5.497 μs | 17.007 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | EncryptAesCbcPad_1KiB | 6.723 μs | 57.318 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | VerifySha256RsaPkcs_1KiB | 19.744 μs | 49.236 ns | 0 B | 0 | 0 | 0 |
| Crypto | CryptoBenchmarks | SignSha256RsaPkcs_1KiB | 334.979 μs | 241.146 ns | 0 B | 0 | 0 | 0 |
| Managed | ManagedTemplateBenchmarks | CreateAesEncryptDecryptTemplate | 20.326 ns | 0.072 ns | 544 B | 363 | 0 | 0 |
| Managed | ManagedTemplateBenchmarks | CreateRsaSignVerifyTemplate | 32.155 ns | 0.122 ns | 880 B | 294 | 0 | 0 |
| Managed | ManagedTemplateBenchmarks | CreateEcSignVerifyTemplate | 33.485 ns | 0.396 ns | 888 B | 296 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | GetSlotCount | 46.424 ns | 0.151 ns | 0 B | 0 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | EnumerateSlots | 107.66 ns | 0.067 ns | 0 B | 0 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | EnumerateMechanisms | 134.489 ns | 2.41 ns | 0 B | 0 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | GetAesCbcPadMechanismFlags | 1.8 μs | 1.678 ns | 0 B | 0 | 0 | 0 |
| Module | ModuleLifecycleBenchmarks | LoadInitializeGetInfoFinalizeDispose | 1.933 μs | 5.099 ns | 384 B | 2 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | CreateUpdateDestroyDataObject | 3.675 μs | 60.045 ns | 784 B | 4 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | FindAesKeyByLabel | 10.646 μs | 117.607 ns | 0 B | 0 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | GenerateDestroyAesKey | 11.97 μs | 572.997 ns | 312 B | 0 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | ReadAesKeyLabelAttribute | 15.448 μs | 35.234 ns | 32 B | 0 | 0 | 0 |
| Object | SessionAndObjectBenchmarks | GenerateDestroyRsaKeyPair | 23.579 ms | 2.14 ms | 1,226 B | 0 | 0 | 0 |
| Session | SessionAndObjectBenchmarks | OpenReadOnlySessionAndGetInfo | 235.345 ns | 0.9 ns | 56 B | 4 | 0 | 0 |
| Session | SessionAndObjectBenchmarks | OpenReadWriteLoginLogoutSession | 265.725 μs | 2.533 μs | 56 B | 0 | 0 | 0 |

> Trend note: compare this file across commits or benchmark workflow artifacts to track whether changes improved or regressed the wrapper over time.
