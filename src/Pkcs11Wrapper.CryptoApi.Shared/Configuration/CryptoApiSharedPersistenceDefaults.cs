namespace Pkcs11Wrapper.CryptoApi.Configuration;

public static class CryptoApiSharedPersistenceDefaults
{
    public const string SqliteProvider = "Sqlite";

    public static string NormalizeProvider(string? provider)
        => string.IsNullOrWhiteSpace(provider)
            ? SqliteProvider
            : provider.Trim();
}
