namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record AdminPkcs11TelemetryExportBundle(
    string Format,
    int SchemaVersion,
    DateTimeOffset ExportedUtc,
    bool RedactedOnly,
    bool MayBeTruncated,
    int EntryCount,
    AdminPkcs11TelemetryQuery Filters,
    AdminPkcs11TelemetryStorageStatus StorageStatus,
    AdminPkcs11TelemetryEntry[] Entries);
