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

public sealed record AdminConfigurationImportResult(
    AdminConfigurationImportMode Mode,
    int ImportedDeviceProfileCount,
    int AddedDeviceProfileCount,
    int UpdatedDeviceProfileCount,
    int RemovedDeviceProfileCount,
    string Summary,
    IReadOnlyList<string> Warnings);
