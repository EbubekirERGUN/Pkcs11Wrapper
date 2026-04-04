using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Caching;
using Pkcs11Wrapper.CryptoApi.Configuration;

namespace Pkcs11Wrapper.CryptoApi.SharedState;

public static class CryptoApiSharedStateServiceCollectionExtensions
{
    public static IServiceCollection AddCryptoApiSharedStateStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<ICryptoApiDistributedHotPathCache, NoOpCryptoApiDistributedHotPathCache>();
        services.AddSingleton<PostgresCryptoApiSharedStateStore>();
        services.AddSingleton<ICryptoApiAuthoritativeSharedStateStore>(static serviceProvider =>
        {
            CryptoApiSharedPersistenceOptions options = serviceProvider.GetRequiredService<IOptions<CryptoApiSharedPersistenceOptions>>().Value;
            return CryptoApiSharedPersistenceDefaults.NormalizeProvider(options.Provider) switch
            {
                CryptoApiSharedPersistenceDefaults.PostgresProvider => serviceProvider.GetRequiredService<PostgresCryptoApiSharedStateStore>(),
                _ => throw new InvalidOperationException($"Unsupported Crypto API shared persistence provider '{options.Provider}'.")
            };
        });
        services.AddSingleton<ICryptoApiSharedStateStore>(static serviceProvider =>
            new CryptoApiHotPathSharedStateStore(
                serviceProvider.GetRequiredService<ICryptoApiAuthoritativeSharedStateStore>(),
                serviceProvider.GetRequiredService<ICryptoApiDistributedHotPathCache>()));

        return services;
    }
}
