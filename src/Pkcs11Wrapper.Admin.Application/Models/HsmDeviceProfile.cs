using System.ComponentModel.DataAnnotations;

namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record HsmDeviceProfile(
    Guid Id,
    string Name,
    string ModulePath,
    string? DefaultTokenLabel,
    string? Notes,
    bool IsEnabled,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc);

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

    public bool IsEnabled { get; set; } = true;
}
