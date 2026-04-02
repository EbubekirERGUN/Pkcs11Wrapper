using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Web.Configuration;

public sealed class AdminBootstrapDeviceSeeder(IOptions<AdminBootstrapDeviceOptions> options, DeviceProfileService deviceProfiles, ILogger<AdminBootstrapDeviceSeeder> logger)
{
    private readonly AdminBootstrapDeviceOptions _options = options.Value;

    public async Task EnsureSeedDataAsync(CancellationToken cancellationToken = default)
    {
        string modulePath = _options.ModulePath.Trim();
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return;
        }

        IReadOnlyList<HsmDeviceProfile> existingProfiles = await deviceProfiles.GetAllAsync(cancellationToken);
        if (existingProfiles.Count > 0)
        {
            logger.LogDebug("Skipping bootstrap device seed because {ProfileCount} device profile(s) already exist.", existingProfiles.Count);
            return;
        }

        HsmDeviceProfile saved = await deviceProfiles.UpsertAsync(
            id: null,
            new HsmDeviceProfileInput
            {
                Name = ResolveName(modulePath),
                ModulePath = modulePath,
                DefaultTokenLabel = Normalize(_options.DefaultTokenLabel),
                Notes = Normalize(_options.Notes),
                VendorId = Normalize(_options.VendorId),
                VendorName = Normalize(_options.VendorName),
                VendorProfileId = Normalize(_options.VendorProfileId),
                VendorProfileName = Normalize(_options.VendorProfileName),
                IsEnabled = _options.IsEnabled
            },
            cancellationToken);

        logger.LogInformation(
            "Seeded bootstrap device profile '{DeviceName}' for module path '{ModulePath}'. This seed only runs when no device profiles exist.",
            saved.Name,
            saved.ModulePath);
    }

    private string ResolveName(string modulePath)
    {
        string configuredName = Normalize(_options.Name) ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(configuredName))
        {
            return configuredName;
        }

        string fileName = Path.GetFileNameWithoutExtension(modulePath);
        return string.IsNullOrWhiteSpace(fileName)
            ? "Bootstrap PKCS#11 module"
            : fileName;
    }

    private static string? Normalize(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
