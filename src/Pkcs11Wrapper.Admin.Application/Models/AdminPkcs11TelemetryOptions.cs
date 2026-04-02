namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed class AdminPkcs11TelemetryOptions
{
    public long ActiveFileMaxBytes { get; set; } = 1 * 1024 * 1024;

    public int RetentionDays { get; set; } = 14;

    public int MaxArchivedFiles { get; set; } = 8;

    public int ExportMaxEntries { get; set; } = 5000;
}
