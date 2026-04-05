namespace Pkcs11Wrapper.Admin.Application.Models;

public enum AdminConfigurationImportMode
{
    Merge = 0,
    ReplaceAll = 1
}

public sealed class AdminConfigurationExportBundle
{
    public string Format { get; init; } = "Pkcs11Wrapper.Admin.Configuration";

    public int SchemaVersion { get; init; } = 1;

    public string ProductName { get; init; } = "Pkcs11Wrapper Admin";

    public string ProductVersion { get; init; } = string.Empty;

    public DateTimeOffset ExportedUtc { get; init; }

    public List<string> IncludedSections { get; init; } = [];

    public List<string> ExcludedSections { get; init; } = [];

    public List<HsmDeviceProfile> DeviceProfiles { get; init; } = [];
}

public sealed record AdminConfigurationImportIssue(
    string Scope,
    string Severity,
    string? DeviceName,
    string? DeviceId,
    string Message);

public sealed record AdminConfigurationImportImpact(
    AdminConfigurationImportMode Mode,
    bool CanImport,
    int FinalDeviceProfileCount,
    int AddedDeviceProfileCount,
    int UpdatedDeviceProfileCount,
    int RemovedDeviceProfileCount,
    int DuplicateDeviceProfileCount,
    int InvalidDeviceProfileCount,
    IReadOnlyList<string> AddedDeviceProfileNames,
    IReadOnlyList<string> UpdatedDeviceProfileNames,
    IReadOnlyList<string> RemovedDeviceProfileNames,
    IReadOnlyList<string> Blockers,
    string Summary);

public sealed record AdminConfigurationImportAnalysis(
    int ExistingDeviceProfileCount,
    int ImportedDeviceProfileCount,
    int ReadyDeviceProfileCount,
    int DuplicateDeviceProfileCount,
    int InvalidDeviceProfileCount,
    AdminConfigurationImportImpact MergeImpact,
    AdminConfigurationImportImpact ReplaceAllImpact,
    IReadOnlyList<AdminConfigurationImportIssue> Issues);

public sealed record AdminConfigurationImportPreview(
    string SourceName,
    string? Format,
    int? SchemaVersion,
    string? ProductName,
    string? ProductVersion,
    DateTimeOffset? ExportedUtc,
    IReadOnlyList<string> IncludedSections,
    IReadOnlyList<string> ExcludedSections,
    IReadOnlyList<string> Problems,
    IReadOnlyList<string> Warnings,
    AdminConfigurationImportAnalysis Analysis);

public sealed record AdminConfigurationImportResult(
    AdminConfigurationImportMode Mode,
    int ImportedDeviceProfileCount,
    int AddedDeviceProfileCount,
    int UpdatedDeviceProfileCount,
    int RemovedDeviceProfileCount,
    string Summary,
    IReadOnlyList<string> Warnings);
