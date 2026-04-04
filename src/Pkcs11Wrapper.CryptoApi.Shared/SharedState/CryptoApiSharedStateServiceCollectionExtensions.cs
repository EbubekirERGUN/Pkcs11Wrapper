using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Configuration;

namespace Pkcs11Wrapper.CryptoApi.SharedState;

public static class CryptoApiSharedStateServiceCollectionExtensions
{
    public static IServiceCollection AddCryptoApiSharedStateStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<SqliteCryptoApiSharedStateStore>();
        services.AddSingleton<PostgresCryptoApiSharedStateStore>();
        services.AddSingleton<ICryptoApiSharedStateStore>(static serviceProvider =>
        {
            CryptoApiSharedPersistenceOptions options = serviceProvider.GetRequiredService<IOptions<CryptoApiSharedPersistenceOptions>>().Value;
            return CryptoApiSharedPersistenceDefaults.NormalizeProvider(options.Provider) switch
            {
                CryptoApiSharedPersistenceDefaults.SqliteProvider => serviceProvider.GetRequiredService<SqliteCryptoApiSharedStateStore>(),
                CryptoApiSharedPersistenceDefaults.PostgresProvider => serviceProvider.GetRequiredService<PostgresCryptoApiSharedStateStore>(),
                _ => throw new InvalidOperationException($"Unsupported Crypto API shared persistence provider '{options.Provider}'.")
            };
        });

        return services;
    }
}
