namespace Pkcs11Wrapper.CryptoApi.Configuration;

public sealed class CryptoApiRequestPathCachingOptions
{
    public const string SectionName = "CryptoApiRequestPathCaching";

    public bool Enabled { get; set; } = true;

    public int AuthenticationEntryLimit { get; set; } = 512;

    public int AuthorizationEntryLimit { get; set; } = 2048;

    public int EntryTtlSeconds { get; set; } = 30;

    public int LastUsedWriteIntervalSeconds { get; set; } = 30;

    internal TimeSpan EntryTtl
        => TimeSpan.FromSeconds(EntryTtlSeconds);

    internal TimeSpan LastUsedWriteInterval
        => TimeSpan.FromSeconds(LastUsedWriteIntervalSeconds);
}
