# Crypto API performance regression suite

`Pkcs11Wrapper` now keeps **service-level Crypto API regression measurements** separate from the existing wrapper `BenchmarkDotNet` suite.

- `docs/benchmarks.md` = wrapper/interoperability microbenchmarks
- `docs/crypto-api-performance.md` = real Crypto API HTTP workloads, throughput, latency, and single-vs-multi-instance behavior

That split is intentional. Issue #152 is about catching **Crypto API workload regressions** before they turn into another round of ad-hoc throughput debugging.

## Design choice

A small **custom closed-loop harness** was chosen instead of trying to stretch `BenchmarkDotNet` into an HTTP/scaling tool.

Why:

- the target is an ASP.NET Core service, not just wrapper call overhead
- we need **single-instance** and **multi-instance** coverage in one committed workflow
- we need **throughput + latency percentiles** for realistic HTTP calls
- we need a repo-owned harness that is easy to read, tweak, and rerun locally
- the suite should stay practical and not pretend to be a full distributed load-testing platform

The harness lives in `benchmarks/Pkcs11Wrapper.CryptoApiPerf` and is orchestrated by `eng/run-cryptoapi-perf.sh`.

## What the suite covers

Every run provisions a temporary local fixture and measures all of these scenarios:

- `single-instance-sign`
- `single-instance-random`
- `single-instance-mixed`
- `multi-instance-sign`
- `multi-instance-random`
- `multi-instance-mixed`

Workload shapes are fixed on purpose:

- **sign**: RS256 sign over a fixed 1 KiB payload
- **random**: 32-byte random generation
- **mixed**: deterministic 70/30 sign/random mix

Topology shapes are also fixed:

- **single-instance**: requests hit one Crypto API host directly
- **multi-instance**: requests hit the repo-owned gateway in front of two Crypto API hosts using round-robin balancing

## Profiles

The harness exposes stable profiles instead of forcing contributors to hand-tune load settings every run:

- `quick` — fast local smoke for workflow validation
- `ci` — short manual GitHub run profile
- `baseline` — longer local run for reviewing and refreshing the committed baseline

## Run locally

Quick validation:

```bash
./eng/run-cryptoapi-perf.sh --profile=quick
```

Canonical local baseline run:

```bash
./eng/run-cryptoapi-perf.sh --profile=baseline
```

Refresh the committed Linux baseline after reviewing the result:

```bash
./eng/run-cryptoapi-perf.sh --profile=baseline --update-docs
```

The script will:

1. provision a temporary SoftHSM fixture
2. provision an ephemeral PostgreSQL container if no connection string is supplied
3. start one direct Crypto API host
4. start a second Crypto API host against the same shared state
5. start the gateway in front of those two hosts
6. seed a dedicated client/key/policy/alias set in shared persistence
7. run the closed-loop workload matrix and write reports

If you already have PKCS#11 env exported and want to reuse it:

```bash
./eng/run-cryptoapi-perf.sh --use-existing-env --profile=baseline
```

## Output locations

Generated artifacts:

- `artifacts/crypto-api-perf/latest/summary.md`
- `artifacts/crypto-api-perf/latest/summary.json`
- `artifacts/crypto-api-perf/latest/<scenario>/scenario.json`
- `artifacts/crypto-api-perf/latest/logs/`

Committed baseline files:

- `docs/crypto-api-performance/latest-linux-softhsm.md`
- `docs/crypto-api-performance/latest-linux-softhsm.json`

The markdown summary is the human-readable review surface.
The JSON summary is the machine-readable baseline/reporting shape for future comparisons.
Per-scenario JSON files preserve the raw scenario summary and sampled failures when something goes wrong.

## GitHub workflow split

The repository intentionally does **not** run this suite on every push.

Instead:

- `.github/workflows/benchmarks.yml` continues to own wrapper microbenchmarks
- `.github/workflows/crypto-api-performance.yml` is a **manual workflow_dispatch lane** for the heavier service-level suite

That keeps the regression workflow available and repeatable without turning normal CI into a noisy throughput lab.

## Practical limitations

This suite is meant to catch regressions, not overclaim capacity.

Be honest about what the numbers mean:

- it is a **single-machine SoftHSM fixture**, not a real networked HSM fleet
- the harness is **closed-loop**, so it is best for relative comparisons across commits, not absolute vendor sizing claims
- the multi-instance lane validates **gateway + shared-state + two-host behavior**, not cross-machine network latency
- local baselines are more trustworthy than hosted-runner throughput numbers for serious performance review
- Windows and vendor-HSM service-level perf automation are out of scope for this first committed suite

That is still enough to catch the class of regressions that previously triggered manual investigations in issues like `#130`, `#131`, `#133`, `#137`, and `#148`.

## Review discipline

A good maintenance loop is:

1. run `quick` while changing the harness/workflow
2. run `baseline` when reviewing performance-sensitive Crypto API changes
3. compare the latest `summary.md` against the committed baseline
4. only refresh `docs/crypto-api-performance/latest-linux-softhsm.*` when the new numbers are representative

This keeps the repo on a repeatable regression path instead of another ad-hoc benchmark notebook.
