# Performance benchmark baseline

- Generated (UTC): 2026-03-31T10:57:27.5071902+00:00
- SDK: 10.0.201
- Runtime: 10.0.5
- Host framework: .NET 10.0.5
- OS: Arch Linux
- Architecture: X64
- PKCS#11 module: `/usr/lib64/softhsm/libsofthsm2.so`
- Benchmark profile: BenchmarkDotNet ShortRun + MemoryDiagnoser

| Category | Suite | Benchmark | Mean | StdDev | Allocated |
| --- | --- | --- | ---: | ---: | ---: |
| Crypto | CryptoBenchmarks | GenerateRandom32 | 149.407 ns | 0.245 ns | n/a |
| Crypto | CryptoBenchmarks | DigestSha256_1KiB | 781.988 ns | 1.122 ns | n/a |
| Crypto | CryptoBenchmarks | DigestSha256Multipart_1KiB | 916.843 ns | 0.26 ns | n/a |
| Crypto | CryptoBenchmarks | DecryptAesCbcPad_1KiB | 5.473 μs | 26.118 ns | n/a |
| Crypto | CryptoBenchmarks | EncryptAesCbcPad_1KiB | 6.249 μs | 7.541 ns | n/a |
| Crypto | CryptoBenchmarks | VerifySha256RsaPkcs_1KiB | 19.652 μs | 19.647 ns | n/a |
| Crypto | CryptoBenchmarks | SignSha256RsaPkcs_1KiB | 333.295 μs | 651.408 ns | n/a |
| Managed | ManagedTemplateBenchmarks | CreateAesEncryptDecryptTemplate | 21.116 ns | 0.097 ns | n/a |
| Managed | ManagedTemplateBenchmarks | CreateEcSignVerifyTemplate | 32.622 ns | 0.065 ns | n/a |
| Managed | ManagedTemplateBenchmarks | CreateRsaSignVerifyTemplate | 32.628 ns | 0.143 ns | n/a |
| Module | ModuleLifecycleBenchmarks | GetSlotCount | 46.424 ns | 0.109 ns | n/a |
| Module | ModuleLifecycleBenchmarks | EnumerateSlots | 104.525 ns | 0.126 ns | n/a |
| Module | ModuleLifecycleBenchmarks | EnumerateMechanisms | 136.503 ns | 0.182 ns | n/a |
| Module | ModuleLifecycleBenchmarks | GetAesCbcPadMechanismFlags | 1.812 μs | 4.89 ns | n/a |
| Module | ModuleLifecycleBenchmarks | LoadInitializeGetInfoFinalizeDispose | 1.904 μs | 4.001 ns | n/a |
| Object | SessionAndObjectBenchmarks | CreateUpdateDestroyDataObject | 3.63 μs | 16.207 ns | n/a |
| Object | SessionAndObjectBenchmarks | FindAesKeyByLabel | 10.704 μs | 143.861 ns | n/a |
| Object | SessionAndObjectBenchmarks | GenerateDestroyAesKey | 12.334 μs | 267.879 ns | n/a |
| Object | SessionAndObjectBenchmarks | ReadAesKeyLabelAttribute | 15.349 μs | 40.627 ns | n/a |
| Object | SessionAndObjectBenchmarks | GenerateDestroyRsaKeyPair | 26.19 ms | 3.813 ms | n/a |
| Session | SessionAndObjectBenchmarks | OpenReadOnlySessionAndGetInfo | 232.799 ns | 0.366 ns | n/a |
| Session | SessionAndObjectBenchmarks | OpenReadWriteLoginLogoutSession | 294.45 μs | 740.833 ns | n/a |

> Trend note: compare this file across commits or benchmark workflow artifacts to track whether changes improved or regressed the wrapper over time.
