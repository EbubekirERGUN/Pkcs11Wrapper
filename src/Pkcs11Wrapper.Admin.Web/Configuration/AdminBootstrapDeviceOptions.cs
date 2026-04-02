namespace Pkcs11Wrapper.Admin.Web.Configuration;

public sealed class AdminBootstrapDeviceOptions
{
    public string Name { get; set; } = string.Empty;

    public string ModulePath { get; set; } = string.Empty;

    public string? DefaultTokenLabel { get; set; }

    public string? Notes { get; set; }

    public string? VendorId { get; set; }

    public string? VendorName { get; set; }

    public string? VendorProfileId { get; set; }

    public string? VendorProfileName { get; set; }

    public bool IsEnabled { get; set; } = true;
}
