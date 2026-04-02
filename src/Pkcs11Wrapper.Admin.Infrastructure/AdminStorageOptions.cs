namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed class AdminStorageOptions
{
    public string DataRoot { get; set; } = string.Empty;

    public string DeviceProfilesFileName { get; set; } = "device-profiles.json";

    public string AuditLogFileName { get; set; } = "audit-log.jsonl";

    public string TelemetryLogFileName { get; set; } = "pkcs11-telemetry.jsonl";

    public string LabTemplatesFileName { get; set; } = "lab-templates.json";
}
