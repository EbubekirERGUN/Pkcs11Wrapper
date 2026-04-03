namespace Pkcs11Wrapper.CryptoApi.Configuration;

public static class CryptoApiHostDefaults
{
    public const string DefaultServiceName = "Pkcs11Wrapper.CryptoApi";
    public const string DefaultApiBasePath = "/api/v1";
    public const string HealthLivePath = "/health/live";
    public const string HealthReadyPath = "/health/ready";

    public static string NormalizeBasePath(string? configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return DefaultApiBasePath;
        }

        string normalized = configuredPath.Trim();
        if (!normalized.StartsWith("/", StringComparison.Ordinal))
        {
            normalized = $"/{normalized}";
        }

        return normalized.Length == 1 ? normalized : normalized.TrimEnd('/');
    }
}
