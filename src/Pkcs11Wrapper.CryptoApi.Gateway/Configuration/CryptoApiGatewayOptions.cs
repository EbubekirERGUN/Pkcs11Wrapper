namespace Pkcs11Wrapper.CryptoApi.Gateway.Configuration;

public sealed class CryptoApiGatewayOptions
{
    public const string SectionName = "CryptoApiGateway";

    public string ServiceName { get; set; } = CryptoApiGatewayDefaults.DefaultServiceName;

    public string ClusterId { get; set; } = CryptoApiGatewayDefaults.DefaultClusterId;

    public string ApiBasePath { get; set; } = CryptoApiGatewayDefaults.DefaultApiBasePath;

    public string LoadBalancingPolicy { get; set; } = "RoundRobin";

    public string CorrelationIdHeaderName { get; set; } = CryptoApiGatewayDefaults.DefaultCorrelationIdHeaderName;

    public long? MaxRequestBodySizeBytes { get; set; } = 1_048_576;

    public GatewayHttpClientOptions HttpClient { get; set; } = new();

    public GatewayHealthCheckOptions HealthChecks { get; set; } = new();

    public List<GatewayDestinationOptions> Destinations { get; set; } = [];
}

public sealed class GatewayHttpClientOptions
{
    public int ActivityTimeoutSeconds { get; set; } = 30;

    public bool DangerousAcceptAnyServerCertificate { get; set; }
}

public sealed class GatewayHealthCheckOptions
{
    public GatewayActiveHealthCheckOptions Active { get; set; } = new();
}

public sealed class GatewayActiveHealthCheckOptions
{
    public bool Enabled { get; set; } = true;

    public int IntervalSeconds { get; set; } = 5;

    public int TimeoutSeconds { get; set; } = 2;

    public int ConsecutiveFailuresThreshold { get; set; } = 2;

    public string Path { get; set; } = CryptoApiGatewayDefaults.HealthReadyPath;

    public string? Query { get; set; }
}

public sealed class GatewayDestinationOptions
{
    public string Name { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;

    public string? Health { get; set; }

    public bool Enabled { get; set; } = true;
}
