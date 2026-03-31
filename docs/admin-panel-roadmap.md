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

Status: planned

Goals:
- key/object detail drawer
- generate/create flows for common AES/RSA scenarios
- attribute editing where supported
- safer destructive flows and richer confirmations

## Phase C - Session operations

Status: planned

Goals:
- richer session detail view
- login/logout controls in session context
- operation visibility improvements
- optional `CloseAllSessions` / session cancel surface per slot/device

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
