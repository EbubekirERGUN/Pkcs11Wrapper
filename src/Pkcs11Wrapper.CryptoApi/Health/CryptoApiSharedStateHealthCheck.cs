using Microsoft.Extensions.Diagnostics.HealthChecks;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Health;

public sealed class CryptoApiSharedStateHealthCheck(ICryptoApiSharedStateStore sharedStateStore) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            CryptoApiSharedStateStatus status = await sharedStateStore.GetStatusAsync(cancellationToken);
            if (!status.Configured)
            {
                return HealthCheckResult.Healthy("Shared persistence is optional and not configured.");
            }

            return HealthCheckResult.Healthy(
                $"Shared persistence is available for {status.ApiClientCount} client(s), {status.ApiClientKeyCount} client key(s), {status.KeyAliasCount} alias(es), and {status.PolicyCount} policy record(s).");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Configured shared persistence could not be opened.", ex);
        }
    }
}
