# Performance benchmarks

`Pkcs11Wrapper` includes a dedicated `BenchmarkDotNet` suite for tracking wrapper overhead and realistic PKCS#11 operation cost over time.

## Why this exists

The goal is not a one-off speed screenshot. The benchmark suite gives the repository a repeatable baseline so we can answer:

- did a refactor improve or regress the wrapper?
- how much overhead do object/session helpers add?
- are key lifecycle and crypto flows getting faster, slower, or noisier over time?
- which changes are worth keeping from a performance point of view?

## Current benchmark coverage

The suite covers the operation families that matter most in this repository:

- managed provisioning-template helpers
- module lifecycle and mechanism discovery
- session open / login / info paths, including concurrent session-info bursts that expose lock contention in hot wrapper validation
- object search, large-slot page browsing, and attribute reads
- object create / update / destroy flows
- AES key generation and RSA keypair generation
- random generation, digest, encrypt, decrypt, sign, verify

Some public overloads share the same underlying native path. For those areas, the suite benchmarks representative forms rather than duplicating every overload with identical work.

## Run locally

Linux:

```bash
./eng/run-benchmarks.sh
```

Linux with docs refresh:

```bash
./eng/run-benchmarks.sh --update-docs
```

Windows PowerShell:

```powershell
.\eng\run-benchmarks.ps1 -DownloadPortable
```

## Output locations

- latest generated summary: `artifacts/benchmarks/latest/summary.md`
- latest generated JSON: `artifacts/benchmarks/latest/summary.json`
- latest GitHub-friendly run report: `artifacts/benchmarks/latest/github-report.md`
- raw BenchmarkDotNet per-suite exports: `artifacts/benchmarks/latest/benchmarkdotnet-results/`
- latest committed Linux baseline markdown: `docs/benchmarks/latest-linux-softhsm.md`
- latest committed Linux baseline JSON: `docs/benchmarks/latest-linux-softhsm.json`

The markdown summary now preserves allocation data (`Allocated`, `Gen0`, `Gen1`, `Gen2`) instead of collapsing managed-memory costs to `n/a`, and the GitHub-friendly report can compare the latest run against the committed Linux baseline.

## Periodic publishing strategy

The repository includes a dedicated GitHub Actions benchmark workflow so we can rerun the same benchmark suite at regular intervals and keep the latest reviewed baseline visible on GitHub.

That workflow now publishes each run in two GitHub-friendly ways:

- a concise job summary showing the latest run date, environment, headline benchmark numbers, allocation figures, and optional baseline deltas
- a downloadable artifact bundle containing the markdown/JSON summary plus raw BenchmarkDotNet CSV, HTML, GitHub-markdown, and log files when available

Benchmark-trigger discipline:

- rerun after benchmark-project changes
- rerun after performance-sensitive source changes in `Pkcs11Wrapper` or `Pkcs11Wrapper.Native`
- rerun after smoke/runtime changes that affect benchmark fixture behavior
- rerun before releases when performance could reasonably have shifted

Recommended maintenance loop:

1. rerun after performance-sensitive wrapper or interop changes
2. rerun before releases
3. refresh the committed Linux baseline markdown + JSON files when the new run is trustworthy and representative
4. keep the README benchmark block aligned with the latest committed baseline date and headline numbers

We do not need a full benchmark history system inside the repository right now; showing the latest trustworthy result with its date is enough.
