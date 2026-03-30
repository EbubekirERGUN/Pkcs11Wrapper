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
Status: **done**

Goals:
- make vendor-path validation more explicit and repeatable
- document env contract and supported expectations
- isolate vendor-specific capability differences cleanly

Acceptance criteria:
- vendor lane documentation improved
- at least one more explicit compatibility path defined
- test expectations clearly distinguish capability-gated vs broken behavior

### 1.5 Mechanism matrix expansion
Status: **done**

Goals:
- widen coverage for RSA OAEP/PSS variants, AES modes, ECDH variants, and edge cases
- cover more negative cases and vendor-sensitive parameter combinations

Acceptance criteria:
- new matrix tests added without making the suite flaky
- unsupported combinations are capability-gated, not silently ignored

Notes:
- added AES-CTR and AES-CBC-PAD matrix coverage alongside the existing AES-GCM / RSA OAEP / RSA PSS / HMAC cases
- new negative checks assert mechanism-parameter rejection paths instead of silently skipping bad parameter combinations

## Phase 2 - PKCS#11 spec coverage

### 2.1 Interface discovery
Status: **done**

- `C_GetInterface`
- `C_GetInterfaceList`

Notes:
- added optional export-based interface discovery that degrades cleanly on modules like current SoftHSM builds that do not expose the v3 entry points
- introduced managed `Pkcs11Interface` projection and ABI/layout coverage for `CK_INTERFACE` / `CK_FUNCTION_LIST_3_0`

### 2.2 Message-based PKCS#11 v3 APIs
Status: **done**

- `C_MessageEncrypt*`
- `C_MessageDecrypt*`
- `C_MessageSign*`
- `C_MessageVerify*`

Notes:
- added span-first managed wrappers for single-shot and begin/next/final message flows
- routed through the discovered PKCS#11 v3 interface instead of assuming `C_GetFunctionList()` returns an extended table

### 2.3 Additional session/user APIs if needed
Status: **done**

- `C_LoginUser`
- `C_SessionCancel`

Notes:
- managed session surface now exposes `LoginUser` and `SessionCancel`
- capability remains v3-interface gated by design

Acceptance criteria for Phase 2:
- managed API shape is reviewed carefully
- NativeAOT compatibility remains intact
- docs and tests cover newly exposed functionality

## Phase 3 - Productization

### 3.1 Compatibility matrix
Status: **done**

- supported platforms
- supported module families / validation targets
- known limitations

### 3.2 Docs and examples
Status: **done**

- production-oriented usage examples
- troubleshooting notes
- vendor caveats

### 3.3 Packaging / release discipline
Status: **done**

- versioning and release notes
- publishing hygiene
- benchmark/perf notes where meaningful

Notes:
- pack metadata added to both projects
- `eng/verify-release.sh` now provides a repeatable restore/build/test/smoke/pack gate for release candidates

## Current top 3 tasks

1. Add a vendor validation target that actually exposes PKCS#11 v3 message APIs so the new capability-gated paths get runtime coverage
2. Expand docs/examples once a concrete v3-capable hardware or software target is chosen
3. Decide whether package publishing should stay manual or move into a guarded/tag-only CI flow
