using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper;
using Pkcs11Wrapper.CryptoApi.Configuration;

namespace Pkcs11Wrapper.CryptoApi.Health;

public sealed class CryptoApiModuleReadinessHealthCheck(IOptions<CryptoApiRuntimeOptions> options) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        string modulePath = options.Value.ModulePath?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Crypto API module path is not configured."));
        }

        try
        {
            using Pkcs11Module module = Pkcs11Module.Load(modulePath);
            return Task.FromResult(HealthCheckResult.Healthy("Configured PKCS#11 module can be loaded."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Configured PKCS#11 module could not be loaded.", ex));
        }
    }
}
