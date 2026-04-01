# PKCS#11 telemetry redaction policy

Telemetry in `Pkcs11Wrapper` is intentionally conservative. It is designed for diagnostics and correlation, not for payload capture.

## Classification buckets

Each `Pkcs11OperationTelemetryEvent` can expose redacted `Fields`. Every field carries a `Pkcs11TelemetryFieldClassification`:

- `SafeMetadata` — non-secret metadata that is safe to log directly.
  - examples: PKCS#11 user/object/mechanism identifiers, boolean capability flags, object class, key type, salt/tag/counter sizes
- `LengthOnly` — raw bytes are never logged; only their size is emitted.
  - examples: plaintext/ciphertext buffers, wrapped-key payloads, random seeds/output, multipart message chunks, AEAD IV/AAD lengths, operation-state blobs
- `Masked` — secret credentials are represented as presence/length only.
  - examples: PINs as `set(len=n)` or `empty`
- `Hashed` — non-secret but potentially identifying byte values are replaced with a stable SHA-256 prefix.
  - examples: usernames, labels, IDs, OAEP source data, ECDH public data, EC point/parameter blobs
- `NeverLog` — the value itself must never be emitted. Telemetry only reports that it was suppressed, optionally with length metadata.
  - examples: `CKA_VALUE`, private exponents, RSA/DSA/DH secret components, imported secret attribute payloads

## Default policy by data type

### Never log raw values

These are always suppressed and never copied into telemetry:

- PIN bytes
- secret/private key material and secret-bearing attributes
- imported/unwrapped key payload attributes (`CKA_VALUE`, private CRT components, DH/DSA secrets, similar standard secret attributes)
- operation state blobs

### Length-only

These payloads keep operational usefulness without leaking contents:

- plaintext / ciphertext / digest / signature inputs and outputs
- wrapped-key blobs and unwrap/import payload byte arrays
- random seeds and generated random output buffers
- AEAD IV / nonce / AAD lengths
- multipart message fragments and generic byte-span inputs

### Hashed

These values can help correlate calls without exposing raw data:

- object labels and IDs
- usernames passed to `C_LoginUser`
- OAEP `sourceData`
- ECDH public data
- EC point / EC params / other identifying public attribute blobs

### Safe metadata

These values are emitted directly:

- slot/session/mechanism identifiers already attached to telemetry events
- user type, object class, key type
- boolean object flags such as token/private/sensitive/extractable/wrap/unwrap/sign/verify/derive
- scalar mechanism metadata such as hash algorithm IDs, MGF IDs, salt lengths, tag bits, counter bits, nonce lengths, AAD lengths
- attribute/template counts and destination buffer sizes

## Implementation notes

The native telemetry layer applies this policy at the PKCS#11 boundary so listeners do not need to guess which fields are safe.

Current coverage includes:

- login / PIN / token-init credential paths
- object search templates and object attribute mutation templates
- key generation, wrap/unwrap, derive, and mechanism parameter summaries
- single-part and multipart digest/encrypt/decrypt/sign/verify flows
- PKCS#11 v3 message-based operations
- random seeding/generation and operation-state restore

If a future API adds new byte payloads, the default should remain conservative: prefer `LengthOnly`, move to `Hashed` only for correlation-friendly public identifiers, and reserve `NeverLog` for secret-bearing attributes and key material.
