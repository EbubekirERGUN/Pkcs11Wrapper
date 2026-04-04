namespace Pkcs11Wrapper.CryptoApi.Configuration;

public static class CryptoApiSharedPersistenceDefaults
{
    public const string SqliteProvider = "Sqlite";
    public const string PostgresProvider = "Postgres";

    public static string NormalizeProvider(string? provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
        {
            return SqliteProvider;
        }

        return provider.Trim().ToLowerInvariant() switch
        {
            "sqlite" => SqliteProvider,
            "postgres" => PostgresProvider,
            "postgresql" => PostgresProvider,
            "npgsql" => PostgresProvider,
            _ => provider.Trim()
        };
    }

    public static bool IsSupportedProvider(string? provider)
        => string.Equals(NormalizeProvider(provider), SqliteProvider, StringComparison.Ordinal)
            || string.Equals(NormalizeProvider(provider), PostgresProvider, StringComparison.Ordinal);
}
