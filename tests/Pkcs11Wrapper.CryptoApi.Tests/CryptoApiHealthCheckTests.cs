using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Health;
using Pkcs11Wrapper.CryptoApi.Runtime;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiHealthCheckTests
{
    [Fact]
    public async Task ReadinessReportsUnhealthyWhenModulePathIsMissing()
    {
        CryptoApiModuleReadinessHealthCheck healthCheck = CreateHealthCheck(modulePath: null);

        HealthCheckResult result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("Crypto API PKCS#11 module path is not configured.", result.Description);
        Assert.NotNull(result.Exception);
    }

    [Fact]
    public async Task ReadinessReportsUnhealthyWhenModuleCannotBeLoaded()
    {
        string missingPath = Path.Combine(Path.GetTempPath(), $"missing-pkcs11-{Guid.NewGuid():N}.so");
        CryptoApiModuleReadinessHealthCheck healthCheck = CreateHealthCheck(missingPath);

        HealthCheckResult result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("Configured PKCS#11 module could not be initialized.", result.Description);
        Assert.NotNull(result.Exception);
    }

    [Fact]
    public async Task SharedStateHealthCheckReportsHealthyWhenPersistenceIsOptionalAndUnconfigured()
    {
        ICryptoApiSharedStateStore store = new PostgresCryptoApiSharedStateStore(Options.Create(new CryptoApiSharedPersistenceOptions()));
        CryptoApiSharedStateHealthCheck healthCheck = new(store);

        HealthCheckResult result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("Shared persistence is optional and not configured.", result.Description);
    }

    private static CryptoApiModuleReadinessHealthCheck CreateHealthCheck(string? modulePath)
        => new(new CryptoApiPkcs11Runtime(Options.Create(new CryptoApiRuntimeOptions { ModulePath = modulePath })));
}
