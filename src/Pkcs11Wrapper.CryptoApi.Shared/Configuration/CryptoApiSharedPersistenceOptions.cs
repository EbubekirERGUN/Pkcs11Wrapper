namespace Pkcs11Wrapper.CryptoApi.Configuration;

public sealed class CryptoApiSharedPersistenceOptions
{
    public const string SectionName = "CryptoApiSharedPersistence";

    public string Provider { get; set; } = CryptoApiSharedPersistenceDefaults.SqliteProvider;

    public string? ConnectionString { get; set; }

    public bool AutoInitialize { get; set; } = true;
}
