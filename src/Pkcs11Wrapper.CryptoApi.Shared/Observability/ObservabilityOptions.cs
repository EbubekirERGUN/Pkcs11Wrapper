namespace Pkcs11Wrapper.Observability;

public sealed class ObservabilityOptions
{
    public const string SectionName = "Observability";

    public bool EnablePrometheusScrapingEndpoint { get; set; } = true;

    public string MetricsPath { get; set; } = "/metrics";

    public static void Normalize(ObservabilityOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        string path = string.IsNullOrWhiteSpace(options.MetricsPath)
            ? "/metrics"
            : options.MetricsPath.Trim();

        if (!path.StartsWith("/", StringComparison.Ordinal))
        {
            path = "/" + path;
        }

        options.MetricsPath = path;
    }
}
