namespace Pkcs11Wrapper.CryptoApi.Configuration;

public sealed class CryptoApiRequestPathRedisOptions
{
    public bool Enabled { get; set; }

    public string? Configuration { get; set; }

    public string InstanceName { get; set; } = "pkcs11wrapper:cryptoapi:";

    public int ConnectTimeoutMilliseconds { get; set; } = 5000;

    public int OperationTimeoutMilliseconds { get; set; } = 1000;

    public int ReconnectCooldownSeconds { get; set; } = 5;

    public int AuthStateRevisionTtlSeconds { get; set; } = 300;

    public int AuthenticationEntryTtlSeconds { get; set; }

    public int AuthorizationEntryTtlSeconds { get; set; }

    internal TimeSpan ReconnectCooldown
        => TimeSpan.FromSeconds(ReconnectCooldownSeconds);

    internal TimeSpan AuthStateRevisionTtl
        => TimeSpan.FromSeconds(AuthStateRevisionTtlSeconds);

    internal TimeSpan ResolveAuthenticationEntryTtl(TimeSpan fallback)
        => AuthenticationEntryTtlSeconds > 0
            ? TimeSpan.FromSeconds(AuthenticationEntryTtlSeconds)
            : fallback;

    internal TimeSpan ResolveAuthorizationEntryTtl(TimeSpan fallback)
        => AuthorizationEntryTtlSeconds > 0
            ? TimeSpan.FromSeconds(AuthorizationEntryTtlSeconds)
            : fallback;
}
