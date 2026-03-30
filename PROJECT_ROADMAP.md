# Pkcs11Wrapper Project Roadmap

## Working model

This repository is being improved toward production readiness with a two-hat workflow:

- **PM / Reviewer hat**: prioritizes work, keeps the roadmap honest, checks acceptance criteria, flags risks, and proposes next tasks.
- **Implementer hat**: makes code changes, adds tests, runs validation, and prepares local commits.

**Push policy:** never push unless Ebubekir explicitly asks for `push`.

## Current baseline

- Workspace repo: `~/.openclaw/workspace/Pkcs11Wrapper`
- Local regression baseline: passing
- NativeAOT smoke baseline: passing
- Configurable PKCS#11 initialize flow has been added

## Phase 1 - Production blockers

### 1.1 Configurable initialize flow
Status: **done**

Acceptance criteria:
- `CK_C_INITIALIZE_ARGS` support exists
- initialize flags/options are exposed in the managed API
- custom mutex callback wiring is supported
- regression and smoke remain green

### 1.2 Stable Linux + SoftHSM baseline
Status: **done**

Acceptance criteria:
- full `./eng/run-regression-tests.sh` passes
- full `./eng/run-smoke-aot.sh` passes
- capability-gated behavior is handled consistently in tests

### 1.3 Concurrency and lifecycle stress coverage
Status: **done**

Goals:
- validate repeated init/finalize cycles
- validate repeated open/close session behavior
- validate invalidation rules under concurrent-ish access patterns
- confirm no hidden state leaks after failed/aborted operations

Acceptance criteria:
- new stress-oriented tests added
- tests are deterministic on SoftHSM
- no regression in baseline suite

### 1.4 Vendor regression lane hardening
Status: **next**

Goals:
- make vendor-path validation more explicit and repeatable
- document env contract and supported expectations
- isolate vendor-specific capability differences cleanly

Acceptance criteria:
- vendor lane documentation improved
- at least one more explicit compatibility path defined
- test expectations clearly distinguish capability-gated vs broken behavior

### 1.5 Mechanism matrix expansion
Status: planned

Goals:
- widen coverage for RSA OAEP/PSS variants, AES modes, ECDH variants, and edge cases
- cover more negative cases and vendor-sensitive parameter combinations

Acceptance criteria:
- new matrix tests added without making the suite flaky
- unsupported combinations are capability-gated, not silently ignored

## Phase 2 - PKCS#11 spec coverage

### 2.1 Interface discovery
- `C_GetInterface`
- `C_GetInterfaceList`

### 2.2 Message-based PKCS#11 v3 APIs
- `C_MessageEncrypt*`
- `C_MessageDecrypt*`
- `C_MessageSign*`
- `C_MessageVerify*`

### 2.3 Additional session/user APIs if needed
- `C_LoginUser`
- `C_SessionCancel`

Acceptance criteria for Phase 2:
- managed API shape is reviewed carefully
- NativeAOT compatibility remains intact
- docs and tests cover newly exposed functionality

## Phase 3 - Productization

### 3.1 Compatibility matrix
- supported platforms
- supported module families / validation targets
- known limitations

### 3.2 Docs and examples
- production-oriented usage examples
- troubleshooting notes
- vendor caveats

### 3.3 Packaging / release discipline
- versioning and release notes
- publishing hygiene
- benchmark/perf notes where meaningful

## Current top 3 tasks

1. Harden vendor regression lane expectations/documentation
2. Expand mechanism matrix with more vendor-sensitive negative cases
3. Start Phase 2 interface discovery (`C_GetInterface` / `C_GetInterfaceList`) design review
