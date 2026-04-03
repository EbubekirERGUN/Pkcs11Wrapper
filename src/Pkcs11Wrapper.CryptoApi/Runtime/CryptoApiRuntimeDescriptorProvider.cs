using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Runtime;

public sealed class CryptoApiRuntimeDescriptorProvider(
    IOptions<CryptoApiHostOptions> hostOptions,
    IOptions<CryptoApiRuntimeOptions> runtimeOptions,
    IOptions<CryptoApiSharedPersistenceOptions> sharedPersistenceOptions,
    TimeProvider timeProvider)
{
    private readonly string _instanceId = Guid.NewGuid().ToString("N");
    private readonly DateTimeOffset _startedAtUtc = timeProvider.GetUtcNow();

    public CryptoApiRuntimeDescriptor Describe()
    {
        string apiBasePath = CryptoApiHostDefaults.NormalizeBasePath(hostOptions.Value.ApiBasePath);
        string provider = CryptoApiSharedPersistenceDefaults.NormalizeProvider(sharedPersistenceOptions.Value.Provider);
        bool sharedPersistenceConfigured = !string.IsNullOrWhiteSpace(sharedPersistenceOptions.Value.ConnectionString);

        return new CryptoApiRuntimeDescriptor(
            ServiceName: string.IsNullOrWhiteSpace(hostOptions.Value.ServiceName)
                ? CryptoApiHostDefaults.DefaultServiceName
                : hostOptions.Value.ServiceName.Trim(),
            InstanceId: _instanceId,
            ApiBasePath: apiBasePath,
            DeploymentModel: "stateless",
            StartedAtUtc: _startedAtUtc,
            ModuleConfigured: !string.IsNullOrWhiteSpace(runtimeOptions.Value.ModulePath),
            SharedPersistenceConfigured: sharedPersistenceConfigured,
            SharedPersistenceProvider: provider,
            SharedReadyAreas: CryptoApiSharedStateConstants.SharedReadyAreas,
            CurrentSurface:
            [
                $"GET {apiBasePath}",
                $"GET {apiBasePath}/runtime",
                $"GET {apiBasePath}/operations",
                $"GET {apiBasePath}/shared-state",
                $"GET {apiBasePath}/auth/self",
                $"GET {CryptoApiHostDefaults.HealthLivePath}",
                $"GET {CryptoApiHostDefaults.HealthReadyPath}"
            ]);
    }
}
