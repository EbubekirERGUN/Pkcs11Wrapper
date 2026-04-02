# PKCS#11 telemetry integrations

`Pkcs11Wrapper` keeps the core PKCS#11 telemetry pipeline intentionally small:

- the native layer emits a single redacted `Pkcs11OperationTelemetryEvent`
- consumers opt in by attaching an `IPkcs11OperationTelemetryListener`
- higher-level logging / tracing stacks are adapters on top of that event stream, not hard dependencies in the PKCS#11 call path

That design keeps the wrapper decoupled while still making it easy to plug into `ILogger`, `ActivitySource`, and OpenTelemetry-style collectors.

It is intentionally **not** the same thing as vendor-native HSM audit ingestion. If you need to understand that boundary, see [vendor-audit-integration.md](vendor-audit-integration.md).

## Available adapters

The main `Pkcs11Wrapper` package exposes these ready-made listeners:

- `Pkcs11LoggerTelemetryListener`
- `Pkcs11ActivityTelemetryListener`
- `Pkcs11CompositeTelemetryListener`
- `Pkcs11TelemetryListeners.Combine(...)`
- `Pkcs11TelemetryListeners.Create(...)`

All of them reuse the same telemetry events and the same redaction policy documented in [telemetry-redaction.md](telemetry-redaction.md).

## `ILogger` integration

```csharp
using Microsoft.Extensions.Logging;
using Pkcs11Wrapper;

using ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
ILogger logger = loggerFactory.CreateLogger("Pkcs11");

IPkcs11OperationTelemetryListener telemetry = new Pkcs11LoggerTelemetryListener(logger);
using Pkcs11Module module = Pkcs11Module.Load("/path/to/pkcs11/module", telemetry);
module.Initialize();
```

Default log-level mapping:

- `Succeeded` -> `Information`
- `ReturnedFalse` -> `Warning`
- `Failed` -> `Error`

The listener writes a compact log message and, by default, adds structured scope properties such as:

- `pkcs11.operation.name`
- `pkcs11.native.operation`
- `pkcs11.status`
- `pkcs11.duration_ms`
- `pkcs11.return_value`
- `pkcs11.slot_id`
- `pkcs11.session_handle`
- `pkcs11.mechanism_type`
- `pkcs11.field.<fieldName>`
- `pkcs11.field_classification.<fieldName>`

Example scope entries for a login call:

- `pkcs11.field.credential.userType = CKU_USER`
- `pkcs11.field.credential.pin = set(len=6)`
- `pkcs11.field_classification.credential.pin = Masked`

You can override the defaults with `Pkcs11LoggerTelemetryOptions` if you want different levels or less scope detail.

## `ActivitySource` / OpenTelemetry-style tracing

```csharp
using System.Diagnostics;
using Pkcs11Wrapper;

using ActivitySource activitySource = new("MyCompany.Security.Pkcs11");

IPkcs11OperationTelemetryListener telemetry = new Pkcs11ActivityTelemetryListener(activitySource);
using Pkcs11Module module = Pkcs11Module.Load("/path/to/pkcs11/module", telemetry);
module.Initialize();
```

Default activity behavior:

- activity name: `pkcs11.{OperationName}`
- activity kind: `Internal`
- tags: core PKCS#11 metadata + redacted telemetry fields
- status mapping:
  - `Succeeded` -> `Ok`
  - `ReturnedFalse` -> `Error` with description `returned_false`
  - `Failed` -> `Error` with the exception message (or PKCS#11 return value when no exception is attached)
- exception handling: when an exception is present, the listener adds an `exception` activity event with type/message/stack-trace tags

This makes the emitted activities straightforward for OpenTelemetry SDKs/exporters to pick up once your process has an `ActivityListener` or OpenTelemetry tracing pipeline configured.

## Combining sinks

If you want logs and traces at the same time, either compose manually or use the helper factory:

```csharp
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Pkcs11Wrapper;

using ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
ILogger logger = loggerFactory.CreateLogger("Pkcs11");
using ActivitySource activitySource = new("MyCompany.Security.Pkcs11");

IPkcs11OperationTelemetryListener? telemetry = Pkcs11TelemetryListeners.Create(
    logger: logger,
    activitySource: activitySource);

using Pkcs11Module module = Pkcs11Module.Load("/path/to/pkcs11/module", telemetry);
module.Initialize();
```

`Pkcs11TelemetryListeners.Create(...)` returns:

- `null` when no sink is requested
- the single listener directly when only one sink is requested
- a `Pkcs11CompositeTelemetryListener` when multiple sinks are requested

The composite listener isolates child-listener failures from each other, matching the wrapper's general rule that observation must not break the underlying PKCS#11 operation flow.

## Redaction still applies

The adapters do **not** bypass the existing redaction layer.

That means the emitted logs / activity tags keep the same guarantees as the raw telemetry events:

- no raw PIN values
- no plaintext / ciphertext payload capture
- no secret key material
- no secret-bearing PKCS#11 attribute values
- only safe metadata, hashed identifiers, masked credentials, and length-only payload summaries

If you need the exact classification policy, see [telemetry-redaction.md](telemetry-redaction.md).
