# Admin telemetry operations

The admin panel persists **only the wrapper's already-redacted PKCS#11 telemetry stream**. This document covers the operational lifecycle controls added around that data so telemetry remains useful without becoming an unbounded storage sink.

## What is stored

The admin telemetry store keeps redacted PKCS#11 operation entries under the admin data root:

- active file: `pkcs11-telemetry.jsonl`
- rotated archives: `pkcs11-telemetry-YYYYMMDD-HHMMSSfff.jsonl`

Each entry includes the existing PKCS#11 context (operation, native call, slot, session handle, mechanism, duration, return value, exception type, redacted fields) plus admin-side correlation hints when available:

- admin actor name
- authentication type
- request/session trace identifier
- correlation id / activity trace id

The viewer uses those fields to link back into matching audit trails.

## Retention and rotation

Telemetry rotation is **size-based** and retention is **age/count-based**.

### Rotation behavior

Before appending a new event, the store checks whether the active JSONL file would exceed the configured `ActiveFileMaxBytes` threshold.

If it would:

1. the current active file is renamed to a timestamped archive
2. a fresh active `pkcs11-telemetry.jsonl` file is created
3. the new event is appended to the fresh active file

This keeps the hottest file small and keeps the newest event in the active file instead of immediately pushing it into an archive.

### Retention behavior

Retention is enforced during read/write lifecycle operations:

- archives older than `RetentionDays` are deleted
- only the newest `MaxArchivedFiles` archives are kept
- empty active files left behind after rotation cleanup are removed

Because rotation + pruning happen inside the telemetry store, storage growth stays bounded even if the viewer/export surface is never opened manually.

Recent-window reads now stream retained JSONL files line-by-line and keep only the requested tail window in memory, so opening the telemetry view no longer requires materializing every retained line when the archive set grows.

## Configuration

Configure the lifecycle policy under `AdminTelemetry`:

```json
{
  "AdminTelemetry": {
    "ActiveFileMaxBytes": 1048576,
    "RetentionDays": 14,
    "MaxArchivedFiles": 8,
    "ExportMaxEntries": 5000
  }
}
```

Meaning:

- `ActiveFileMaxBytes`: max size of the hot JSONL file before rotation
- `RetentionDays`: delete retained telemetry older than this many days (`0` disables age pruning)
- `MaxArchivedFiles`: keep at most this many rotated archives (`0` means only the active file remains)
- `ExportMaxEntries`: hard cap for download/export responses

## Safe export/download

The admin app exposes a first-class redacted telemetry export endpoint:

- `GET /telemetry/export`

Supported query parameters mirror the viewer filters:

- `take`
- `search`
- `device`
- `slot`
- `operation`
- `mechanism`
- `status`
- `timeRange`

Export characteristics:

- JSON payload with metadata + filtered entries
- server-side cap via `ExportMaxEntries`
- `MayBeTruncated=true` when more retained matches existed than were emitted
- no raw PINs, payload bytes, wrapped blobs, or secret-bearing attributes are introduced by export

Exports are also audited through the admin audit log.

## Correlation with audit review

The telemetry viewer now surfaces request/audit correlation when the admin action ran inside an authenticated request context:

- actor badge
- auth type badge
- request/session trace text
- direct link into `/audit?q=...`

The audit page search now matches session trace ids, remote IP, and user agent text so a telemetry row can pivot into a narrower operational review trail quickly.

## Operational guidance

- Use the viewer for **wrapper-side PKCS#11 call context**.
- Use the audit log for **who/when/action** traceability.
- Use export when you need to hand a redacted retained window to another operator or attach it to an investigation artifact.
- Do not treat wrapper telemetry as a substitute for vendor-native HSM audit facilities.
