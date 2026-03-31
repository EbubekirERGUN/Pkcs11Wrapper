# Admin panel roadmap

## Goal

Build a Blazor Server administration surface on top of `Pkcs11Wrapper` so operators can:

- register HSM device profiles
- inspect slots/tokens
- inspect and manage keys/objects
- monitor application-owned sessions
- review audit events
- run controlled PKCS#11 diagnostic/lab operations against a connected module

## Phase A - Foundation (started)

Status: **done**

Delivered:
- `Pkcs11Wrapper.Admin.Application`
- `Pkcs11Wrapper.Admin.Infrastructure`
- `Pkcs11Wrapper.Admin.Web`
- `Pkcs11Wrapper.Admin.Tests`
- JSON-backed device profile + audit storage
- Blazor Server pages for Devices / Slots / Keys / Sessions / Audit Logs
- basic app-owned session registry
- slot and key inspection via `Pkcs11Wrapper`
- destructive key action scaffold (`DestroyObject` via explicit confirmation)

Acceptance criteria:
- solution builds
- admin tests pass
- web host builds cleanly
- device CRUD, slot browsing, key browsing, session list, and audit list all exist

## Phase B - Key management expansion

Status: delivered, with optional follow-on polish

Delivered in current slice:
- richer object detail panel with readable attribute inspection, object size, and common capability/flag summaries
- practical key-management flows for token operators: AES key generation and RSA key-pair generation
- stronger destructive flow with typed confirmation text + explicit permanent-deletion acknowledgement
- admin-layer validation tests covering key-generation request validation and destroy confirmation rules
- AES raw-value import/create flow via `C_CreateObject` for tokens that allow secret-key object creation
- object attribute editing panel for writable attributes (`Label`, `Id`, selected capability booleans, and related flags) via `C_SetAttributeValue`
- safer key/object UX: edit action from table/detail, clearer capability summaries, and explicit warning that token policy still decides what is mutable

Goals:
- key/object detail drawer
- generate/create flows for common AES/RSA scenarios
- attribute editing where supported
- safer destructive flows and richer confirmations

Remaining for Phase B:
- deeper mechanism-aware affordances (for example conditional wrap/unwrap presets per slot capabilities)
- consider fuller template libraries if operators need reusable multi-object provisioning recipes beyond one-off copy flows

## Phase C - Session operations

Status: delivered, with optional follow-on polish

Delivered in current slice:
- richer tracked-session detail panel with state, flags, device error, auth-state summary, and notes
- login/logout controls directly against the tracked session context
- operation visibility improvements through last-operation, auth-state, and slot/session metadata
- tracked-session `C_SessionCancel` control and slot-level `CloseAllSessions` trigger from the admin panel
- explicit invalidated-session UX: tracked sessions now record/present invalidation reason after `CloseAllSessions` or broken lifecycle states, with control gating for stale sessions
- grouped/filterable session table so high-volume tracked-session lists stay readable while healthy vs invalidated states remain obvious

Remaining for Phase C:
- optionally track more PKCS#11-specific invalidation categories if vendors surface richer error codes in session lifecycle failures

## Phase D - Security and ops hardening

Status: delivered for the current local-host scope

Goals:
- protected secret storage for optional cached credentials ✅
- role-based authorization (viewer/operator/admin) ✅
- immutable audit enhancements ✅
- configuration export/import ✅
- bootstrap credential rotation + local user management ✅

Delivered in current slice:
- local cookie-backed authentication with a bootstrap admin credential seeded into `App_Data/bootstrap-admin.txt` on first run, plus role claims for `viewer` / `operator` / `admin`
- service-layer authorization checks inside `HsmAdminService`, so privileged operations are blocked even if UI gating is bypassed
- UI action gating that preserves existing screens while limiting write/destructive flows to operator/admin and device-profile management to admin
- Data Protection-backed protected PIN cache for the current app shape, with opt-in remember toggles on slot/key/session workflows and encrypted-at-rest storage under `App_Data`
- tamper-evident audit chaining via sequence number + previous hash + entry hash, plus actor roles/auth/request metadata and integrity verification surfaced in the audit page
- admin-only configuration transfer slice: export endpoint + configuration page, JSON bundle format, merge/replace-all import modes, audit coverage, and explicit exclusion of local secrets/users/audit history/Data Protection keys from the transferable bundle
- admin-only user/security management slice: local Users page, bootstrap notice visibility + retirement, local user creation, password rotation, role updates, self-protection rules, and audit coverage for user-management events

Current boundaries:
- this is a strong local-host hardening step, not a full multi-user identity system; credentials remain local-file-backed and should be rotated before broader/shared deployment
- protected PIN storage relies on local ASP.NET Core Data Protection keys on the same host; that is appropriate for the current embedded app shape but not equivalent to an external HSM/KMS-backed secret vault
- configuration transfer currently covers device profiles only; admin users, bootstrap credentials, audit history, protected PIN cache, and Data Protection keys intentionally stay local to the host
- local user management currently targets a single-host embedded admin deployment; it is not yet a substitute for external IdP/IAM, MFA, or centralized audit/secret governance

## Phase E - UX / product polish

Status: in progress

Goals:
- dashboard cards and health widgets
- filtering/sorting/paging
- operator-facing PKCS#11 diagnostic / lab console
- release-ready docs and screenshots
- optional API split if the web host needs to be decoupled later

## Newly delivered slice summary

- Phase E first polish slice delivered: dashboard health/ops summary cards, quick actions, users-page filtering/sorting, audit filtering + paging, and a local admin ops/recovery runbook (`docs/admin-ops-recovery.md`)
- Phase E second polish slice delivered: devices-page summary/filter/sort ergonomics, slots-page summary/token filtering/selected-device session visibility, and sessions-page search/filter/sort + filtered/invalidated bulk-close actions
- Phase E third polish slice delivered: keys-page summary cards, client-side search/class/capability filters, sorting + paging, and a reusable/tested `KeyObjectListView` helper so heavy object lists stay manageable
- capability/mechanism-aware key-management UX: slot-level mechanism probing, pre-submit warnings, and disabled generate/import actions when the selected slot obviously cannot satisfy them
- object edit affordances are now more object-aware: obvious unsupported toggles are disabled based on object class + `CKA_MODIFIABLE` visibility
- object copy workflow delivered via `C_CopyObject`, including label/ID/capability override template fields and admin-layer validation
- operator-facing PKCS#11 Lab page delivered: controlled transient-session diagnostic operations for module info, interface discovery, slot snapshot, mechanism list/info, session info, RNG, digest, and object search; plus request validation, audit logging, and protected-PIN reuse
- PKCS#11 Lab second wave delivered: sign/verify and encrypt/decrypt experiments with handle + mechanism input, payload mode selection (UTF-8 vs hex), result inspection, parameterized-mechanism warnings, and validation rules for common operator mistakes
- PKCS#11 Lab third wave delivered: object inspection, key wrap, and constrained AES unwrap flows; handle reuse from Keys/Find Objects output, unwrap target-template controls, and wrap/unwrap capability warnings were added without turning the lab into an unrestricted raw-call shell
- PKCS#11 Lab fourth wave delivered: raw attribute-code reads with status/length/raw-byte inspection, plus selected-object-assisted presets from the Keys page so operators can jump into inspect/raw-attribute/sign/verify/encrypt/decrypt/wrap/unwrap lab flows with prefilled device/slot/handle/mechanism context
- PKCS#11 Lab fifth wave delivered: AES-CBC / AES-CTR / AES-GCM parameter editor support for lab crypto operations, multi-attribute batch raw-read support, and corrected AES mechanism preset mappings so object-driven lab presets align with the wrapper's mechanism constants
- PKCS#11 Lab sixth wave delivered: RSA OAEP / RSA PSS parameter editor support, RSA-oriented Keys→Lab presets (OAEP encrypt/decrypt, PSS sign/verify), and query-bound lab preset propagation for parameter profile + RSA hash/salt context
- PKCS#11 Lab seventh wave delivered: in-page scenario recorder/history with one-click request replay and chain helpers (sign→verify, encrypt→decrypt, wrap→unwrap, inspect created handle), plus named attribute/code-set preset library support for raw attribute reads
