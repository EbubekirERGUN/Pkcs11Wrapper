using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Health;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiHealthCheckTests
{
    [Fact]
    public async Task ReadinessReportsUnhealthyWhenModulePathIsMissing()
    {
        CryptoApiModuleReadinessHealthCheck healthCheck = CreateHealthCheck(modulePath: null);

        HealthCheckResult result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("Crypto API module path is not configured.", result.Description);
    }

    [Fact]
    public async Task ReadinessReportsUnhealthyWhenModuleCannotBeLoaded()
    {
        string missingPath = Path.Combine(Path.GetTempPath(), $"missing-pkcs11-{Guid.NewGuid():N}.so");
        CryptoApiModuleReadinessHealthCheck healthCheck = CreateHealthCheck(missingPath);

        HealthCheckResult result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("Configured PKCS#11 module could not be loaded.", result.Description);
        Assert.NotNull(result.Exception);
    }

    private static CryptoApiModuleReadinessHealthCheck CreateHealthCheck(string? modulePath)
        => new(Options.Create(new CryptoApiRuntimeOptions { ModulePath = modulePath }));
}
