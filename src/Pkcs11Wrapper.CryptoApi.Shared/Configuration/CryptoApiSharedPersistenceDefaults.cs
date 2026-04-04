namespace Pkcs11Wrapper.CryptoApi.Configuration;

public static class CryptoApiSharedPersistenceDefaults
{
    public const string PostgresProvider = "Postgres";

    public static string NormalizeProvider(string? provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
        {
            return PostgresProvider;
        }

        return provider.Trim().ToLowerInvariant() switch
        {
            "postgres" => PostgresProvider,
            "postgresql" => PostgresProvider,
            "npgsql" => PostgresProvider,
            _ => provider.Trim()
        };
    }

    public static bool IsSupportedProvider(string? provider)
        => string.Equals(NormalizeProvider(provider), PostgresProvider, StringComparison.Ordinal);
}
