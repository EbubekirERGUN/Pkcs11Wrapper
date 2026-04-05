namespace Pkcs11Wrapper.CryptoApi.Gateway.Configuration;

public static class CryptoApiGatewayDefaults
{
    public const string DefaultServiceName = "Pkcs11Wrapper.CryptoApi.Gateway";
    public const string DefaultClusterId = "crypto-api-fleet";
    public const string DefaultApiBasePath = "/api/v1";
    public const string DefaultCorrelationIdHeaderName = "X-Correlation-Id";
    public const string HealthLivePath = "/health/live";
    public const string HealthReadyPath = "/health/ready";
    public const string RuntimePath = "/gateway/runtime";

    public static string NormalizeBasePath(string? path)
    {
        string trimmed = string.IsNullOrWhiteSpace(path)
            ? DefaultApiBasePath
            : path.Trim();

        if (!trimmed.StartsWith("/", StringComparison.Ordinal))
        {
            trimmed = "/" + trimmed;
        }

        return trimmed.Length > 1
            ? trimmed.TrimEnd('/')
            : trimmed;
    }

    public static string NormalizeDestinationAddress(string address)
    {
        string trimmed = address.Trim();
        return trimmed.EndsWith("/", StringComparison.Ordinal)
            ? trimmed
            : trimmed + "/";
    }
}
