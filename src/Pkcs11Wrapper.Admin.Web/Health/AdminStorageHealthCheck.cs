using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Configuration;

namespace Pkcs11Wrapper.Admin.Web.Health;

public sealed class AdminStorageHealthCheck(IOptions<AdminStorageOptions> options) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        string dataRoot = options.Value.DataRoot?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(dataRoot))
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Admin storage root is not configured."));
        }

        try
        {
            Directory.CreateDirectory(dataRoot);
            Directory.CreateDirectory(AdminHostDefaults.GetKeysRoot(dataRoot));
            Directory.CreateDirectory(AdminHostDefaults.GetHomeRoot(dataRoot));

            string tempRoot = AdminHostDefaults.GetTempRoot(dataRoot);
            Directory.CreateDirectory(tempRoot);

            string probePath = Path.Combine(tempRoot, $".healthcheck-{Guid.NewGuid():N}");
            File.WriteAllText(probePath, "ok");
            File.Delete(probePath);

            return Task.FromResult(HealthCheckResult.Healthy("Admin storage root and runtime writable directories are available."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Admin storage root or runtime writable directories are unavailable.", ex));
        }
    }
}
