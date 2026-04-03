namespace Pkcs11Wrapper.CryptoApi.Configuration;

public sealed class CryptoApiRateLimitingOptions
{
    public const string SectionName = "CryptoApiRateLimiting";

    public bool Enabled { get; set; } = true;

    public CryptoApiSlidingWindowRateLimitOptions Authentication { get; set; } = new()
    {
        PermitLimit = 60,
        WindowSeconds = 60,
        SegmentsPerWindow = 6,
        QueueLimit = 0
    };

    public CryptoApiSlidingWindowRateLimitOptions Operations { get; set; } = new()
    {
        PermitLimit = 600,
        WindowSeconds = 60,
        SegmentsPerWindow = 6,
        QueueLimit = 0
    };

    public static bool IsValid(CryptoApiSlidingWindowRateLimitOptions? options)
        => options is not null
            && options.PermitLimit > 0
            && options.WindowSeconds > 0
            && options.SegmentsPerWindow > 0
            && options.QueueLimit >= 0;
}

public sealed class CryptoApiSlidingWindowRateLimitOptions
{
    public int PermitLimit { get; set; }

    public int WindowSeconds { get; set; }

    public int SegmentsPerWindow { get; set; }

    public int QueueLimit { get; set; }
}
