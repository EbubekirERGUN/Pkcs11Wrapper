namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record AdminPkcs11TelemetryStorageStatus(
    long ActiveFileBytes,
    int ArchivedFileCount,
    int RetainedFileCount,
    long RetainedBytes,
    long ActiveFileMaxBytes,
    int RetentionDays,
    int MaxArchivedFiles,
    int ExportMaxEntries);
