# Crypto API performance regression baseline

- Generated (UTC): 2026-04-05T07:15:47.3972942+00:00
- Profile: baseline
- Warm-up: 10 s
- Measurement window: 30 s
- Single-instance concurrency: 8
- Multi-instance concurrency: 16
- SDK: 10.0.201
- Runtime: 10.0.4
- Host framework: .NET 10.0.5
- OS: Arch Linux
- Architecture: X64
- PKCS#11 module: `/usr/lib64/softhsm/libsofthsm2.so`
- Token label: `Pkcs11Wrapper CI Token`
- Single-instance target: `single-instance-direct`
- Multi-instance target: `multi-instance-gateway`

## Scenario results

| Scenario | Topology | Workload | Req/s | Mean | P95 | P99 | Max | Ok | Fail | Baseline Δ req/s | Baseline Δ P95 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| multi-instance-mixed | multi-instance | mixed | 11704.97 | 1.37 ms | 2.62 ms | 3.33 ms | 69.68 ms | 351,149 | 0 | n/a | n/a |
| multi-instance-random | multi-instance | random | 123366.27 | 0.13 ms | 0.24 ms | 0.5 ms | 36.87 ms | 3,700,988 | 0 | n/a | n/a |
| multi-instance-sign | multi-instance | sign | 8818.67 | 1.81 ms | 2.82 ms | 3.51 ms | 54.3 ms | 264,560 | 0 | n/a | n/a |
| single-instance-mixed | single-instance | mixed | 10959.97 | 0.73 ms | 1.27 ms | 1.42 ms | 48.9 ms | 328,799 | 0 | n/a | n/a |
| single-instance-random | single-instance | random | 320355.4 | 0.02 ms | 0.03 ms | 0.05 ms | 54.3 ms | 9,610,662 | 0 | n/a | n/a |
| single-instance-sign | single-instance | sign | 8045.97 | 0.99 ms | 1.26 ms | 1.55 ms | 53.86 ms | 241,379 | 0 | n/a | n/a |

## Notes

- Single-instance scenarios hit one Crypto API host directly.
- Multi-instance scenarios hit a local gateway fronting two Crypto API hosts with round-robin balancing.
- Workload mix is deterministic and the harness is closed-loop, so the suite is good for regression detection, not vendor-certified capacity claims.
- SoftHSM on one machine is a practical regression fixture, not a substitute for multi-host or real-HSM validation.

> Trend note: compare this file across commits or rerun artifacts to spot request-rate drops and latency-tail regressions before they escape into manual investigations.
