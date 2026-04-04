namespace Pkcs11Wrapper.CryptoApi.Configuration;

public sealed class CryptoApiRequestPathRedisOptions
{
    public bool Enabled { get; set; }

    public string? Configuration { get; set; }

    public string InstanceName { get; set; } = "pkcs11wrapper:cryptoapi:";

    public int ConnectTimeoutMilliseconds { get; set; } = 5000;

    public int OperationTimeoutMilliseconds { get; set; } = 1000;

    public int AuthStateRevisionTtlSeconds { get; set; } = 30;

    internal TimeSpan AuthStateRevisionTtl
        => TimeSpan.FromSeconds(AuthStateRevisionTtlSeconds);
}
