using System.ComponentModel.DataAnnotations;

namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record HsmDeviceVendorMetadata(
    string VendorId,
    string VendorName,
    string? ProfileId,
    string? ProfileName);

public sealed record HsmDeviceProfile(
    Guid Id,
    string Name,
    string ModulePath,
    string? DefaultTokenLabel,
    string? Notes,
    bool IsEnabled,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    HsmDeviceVendorMetadata? Vendor = null);

public sealed class HsmDeviceProfileInput
{
    [Required]
    [StringLength(128)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [StringLength(1024)]
    public string ModulePath { get; set; } = string.Empty;

    [StringLength(128)]
    public string? DefaultTokenLabel { get; set; }

    [StringLength(2048)]
    public string? Notes { get; set; }

    [StringLength(64)]
    public string? VendorId { get; set; }

    [StringLength(128)]
    public string? VendorName { get; set; }

    [StringLength(64)]
    public string? VendorProfileId { get; set; }

    [StringLength(128)]
    public string? VendorProfileName { get; set; }

    public bool IsEnabled { get; set; } = true;
}
