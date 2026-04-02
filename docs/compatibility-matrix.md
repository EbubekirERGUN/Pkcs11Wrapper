# Compatibility matrix

## Validated baseline

| Area | Status | Notes |
| --- | --- | --- |
| OS | Linux | Primary runtime validation target (fixture-backed regression + NativeAOT smoke) |
| OS | Windows | Supported for fixture-backed runtime regression and `win-x64` NativeAOT smoke through SoftHSM-for-Windows |
| Runtime | .NET 10 | Pinned via `global.json` |
| NativeAOT | Supported | Validated by `eng/run-smoke-aot.sh` on Linux and `eng/run-smoke-aot.ps1` on Windows |
| Reference module | SoftHSM v2 | Default local + CI regression target |
| Optional vendor lane | Supported | Via `eng/run-regression-tests.sh --use-existing-env` and `docs/vendor-regression.md` |

## PKCS#11 surface status

| Capability area | Status | Validation notes |
| --- | --- | --- |
| Core module lifecycle (`C_Initialize`, `C_Finalize`, `C_GetInfo`) | Supported | Covered by API surface and smoke/regression flows |
| Slot / token / mechanism enumeration | Supported | SoftHSM regression coverage |
| Session lifecycle + login/logout | Supported | SoftHSM regression coverage |
| Configurable initialize args / mutex callbacks | Supported | Managed + native API shape coverage |
| Object search / attribute access / create / destroy | Supported | SoftHSM regression coverage |
| Single-part crypto | Supported | SoftHSM regression coverage |
| Multipart crypto + operation state | Supported | SoftHSM regression coverage |
| Recover / combined update flows | Supported | Managed API + runtime coverage |
| Function status / cancel | Capability-gated | Exposed; returns false on modules that report unsupported / non-parallel |
| Interface discovery (`C_GetInterface*`) | Supported | Runtime-covered on Linux via the deterministic v3 shim; SoftHSM remains the capability-absent reference |
| PKCS#11 v3 message APIs (`C_Message*`) | Supported | Runtime-covered on Linux via the deterministic v3 shim; absent SoftHSM exports remain explicitly validated as capability-absent |
| `C_LoginUser` / `C_SessionCancel` | Supported | Runtime-covered on Linux via the deterministic v3 shim |

## Known limitations

- PKCS#11 v3 runtime validation now uses a deterministic Linux-built shim rather than a vendor module, so it validates marshalling/runtime behavior but not vendor-specific semantics.
- Windows NativeAOT validation now exists, but Linux still remains the deepest day-to-day validation environment because it is the primary benchmark baseline and the most feature-complete local automation path.
- AWS CloudHSM now has a documented standard-PKCS#11 support path plus admin-panel read-only→read-write session fallback guidance, but it is not yet backed by live CloudHSM CI or a real-cluster regression lane.
- Azure Cloud HSM now has a documented **direct** PKCS#11 support path for the current repo, but that path still depends on a prepared Azure host runtime (`azcloudhsm_client`, `azcloudhsm_resource.cfg`, `azcloudhsm_application.cfg`, `PO.crt`), private-network access to the cluster, and real Azure validation; Azure Managed HSM remains a different Key Vault/API boundary.
- Google Cloud HSM now has a documented indirect support path through Google's kmsp11 Cloud KMS adapter, but it still depends on real Google auth/config, host-level `KMS_PKCS11_CONFIG`, and live cloud access for honest end-to-end validation.
- IBM Cloud Hyper Protect Crypto Services now has a documented **direct** PKCS#11 support path for the current repo through IBM's Linux EP11 client library plus `grep11client.yaml` / `EP11CLIENT_CFG`, but that path still requires real HPCS endpoint/auth access for honest end-to-end validation and does **not** imply GREP11 gRPC or Windows direct-PKCS#11 support in the current repo boundary.
- Oracle OCI Dedicated KMS now has a documented direct PKCS#11 support path for the current repo, but that path is Linux-first (`oci-hsm-client` + `oci-hsm-pkcs11` + `client_daemon`) and is not yet backed by live OCI CI or a checked-in vendor-regression profile; Oracle's reviewed Windows docs remain CNG/KSP rather than the current PKCS#11 wrapper/admin boundary.
- Mechanism parameter helpers are intentionally selective; uncommon mechanisms may still require raw parameter bytes.
- Packaging discipline is defined in `docs/release.md`, but external package publication is still a maintainer action rather than an automated CI publish step.
