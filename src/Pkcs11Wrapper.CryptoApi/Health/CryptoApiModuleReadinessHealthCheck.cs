using Microsoft.Extensions.Diagnostics.HealthChecks;
using Pkcs11Wrapper;
using Pkcs11Wrapper.CryptoApi.Operations;
using Pkcs11Wrapper.CryptoApi.Runtime;

namespace Pkcs11Wrapper.CryptoApi.Health;

public sealed class CryptoApiModuleReadinessHealthCheck(CryptoApiPkcs11Runtime runtime) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            IReadOnlyList<string> backends = runtime.GetNamedBackendNames();
            if (backends.Count == 0)
            {
                Pkcs11Module module = runtime.GetInitializedModule();
                _ = module.GetInfo();
                return Task.FromResult(HealthCheckResult.Healthy("Configured PKCS#11 module is initialized and ready."));
            }

            foreach (string backend in backends)
            {
                Pkcs11Module module = runtime.GetInitializedModule(backend);
                _ = module.GetInfo();
            }

            return Task.FromResult(HealthCheckResult.Healthy($"Configured PKCS#11 backends are initialized and ready ({backends.Count} backend(s))."));
        }
        catch (CryptoApiOperationConfigurationException ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(ex.Message, ex));
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Configured PKCS#11 module could not be initialized.", ex));
        }
    }
}
