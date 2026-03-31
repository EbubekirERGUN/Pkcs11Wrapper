# Admin panel roadmap

## Goal

Build a Blazor Server administration surface on top of `Pkcs11Wrapper` so operators can:

- register HSM device profiles
- inspect slots/tokens
- inspect and manage keys/objects
- monitor application-owned sessions
- review audit events

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

Status: in progress

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

Status: in progress

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

Status: planned

Goals:
- protected secret storage for optional cached credentials
- role-based authorization (viewer/operator/admin)
- immutable audit enhancements
- configuration export/import

## Phase E - UX / product polish

Status: planned

Goals:
- dashboard cards and health widgets
- filtering/sorting/paging
- release-ready docs and screenshots
- optional API split if the web host needs to be decoupled later

## Newly delivered slice summary

- capability/mechanism-aware key-management UX: slot-level mechanism probing, pre-submit warnings, and disabled generate/import actions when the selected slot obviously cannot satisfy them
- object edit affordances are now more object-aware: obvious unsupported toggles are disabled based on object class + `CKA_MODIFIABLE` visibility
- object copy workflow delivered via `C_CopyObject`, including label/ID/capability override template fields and admin-layer validation
