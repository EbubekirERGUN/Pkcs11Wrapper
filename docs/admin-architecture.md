# Admin architecture seams

This note captures the admin-panel refactor that split the larger monoliths before more feature work lands.

## Service-side seams

- `HsmAdminService` stays the public orchestration surface for authorization, audit logging, and device/session lifecycle.
- `HsmAdminObjectCatalog` owns low-level object enumeration, summary/detail shaping, object-class/key-type formatting, and shared attribute-read helpers.
- `HsmAdminKeyPageBrowser` owns keys-page paging behavior:
  - handle-sorted requests use a streaming cursor path so page 1 stops after `pageSize + 1` summary reads
  - class/capability filters are pushed into `Pkcs11ObjectSearchParameters`
  - other sort modes still page on the server, but they intentionally fall back to full-scan sort materialization
- `HsmKeyObjectQuery` is the shared filter/sort primitive used by both the web layer and the server-side fallback path, so query semantics live in one place.

## Wrapper seam for batched summary reads

- `Pkcs11Session.GetAttributeValues(...)` now exposes batched `C_GetAttributeValue` reads.
- The admin keys/object summary path uses that batch read for label/id/class/key-type/capability summaries instead of issuing one PKCS#11 round trip per attribute.
- Detail views still keep the more explicit per-attribute flow where status fidelity matters more than list throughput.

## Page seams

- `Keys.razor` now keeps markup only; `Keys.razor.cs` owns state, paging navigation, and action handlers.
- `Pkcs11Lab.razor` now keeps markup only; `Pkcs11Lab.razor.cs` owns request state, query hydration, and execution wiring.
- Existing page-specific helpers remain separate and testable:
  - `KeyObjectListView`
  - `Pkcs11LabView`
  - `AdminDashboardView`

## Paging trade-off

The fast path is the default `handle` sort because it supports true streaming cursor pagination. Label/class/capability sorting still runs server-side, but it requires a fallback full scan so the sort order stays correct.
