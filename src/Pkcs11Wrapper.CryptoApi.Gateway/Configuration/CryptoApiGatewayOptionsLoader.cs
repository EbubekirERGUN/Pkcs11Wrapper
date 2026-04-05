using System.Globalization;
using Yarp.ReverseProxy.LoadBalancing;

namespace Pkcs11Wrapper.CryptoApi.Gateway.Configuration;

public static class CryptoApiGatewayOptionsLoader
{
    public static CryptoApiGatewayOptions Load(IConfiguration configuration)
    {
        CryptoApiGatewayOptions options = configuration
            .GetSection(CryptoApiGatewayOptions.SectionName)
            .Get<CryptoApiGatewayOptions>() ?? new CryptoApiGatewayOptions();

        Normalize(options);
        Validate(options);
        return options;
    }

    public static void Normalize(CryptoApiGatewayOptions options)
    {
        options.ServiceName = string.IsNullOrWhiteSpace(options.ServiceName)
            ? CryptoApiGatewayDefaults.DefaultServiceName
            : options.ServiceName.Trim();
        options.ClusterId = string.IsNullOrWhiteSpace(options.ClusterId)
            ? CryptoApiGatewayDefaults.DefaultClusterId
            : options.ClusterId.Trim();
        options.ApiBasePath = CryptoApiGatewayDefaults.NormalizeBasePath(options.ApiBasePath);
        options.LoadBalancingPolicy = string.IsNullOrWhiteSpace(options.LoadBalancingPolicy)
            ? LoadBalancingPolicies.RoundRobin
            : options.LoadBalancingPolicy.Trim();
        options.CorrelationIdHeaderName = string.IsNullOrWhiteSpace(options.CorrelationIdHeaderName)
            ? CryptoApiGatewayDefaults.DefaultCorrelationIdHeaderName
            : options.CorrelationIdHeaderName.Trim();
        options.HealthChecks ??= new GatewayHealthCheckOptions();
        options.HttpClient ??= new GatewayHttpClientOptions();
        options.Destinations ??= [];

        NormalizeHealthChecks(options.HealthChecks);
        NormalizeDestinations(options.Destinations);
    }

    private static void NormalizeHealthChecks(GatewayHealthCheckOptions? healthChecks)
    {
        if (healthChecks is null)
        {
            return;
        }

        healthChecks.Active ??= new GatewayActiveHealthCheckOptions();
        healthChecks.Active.Path = CryptoApiGatewayDefaults.NormalizeBasePath(healthChecks.Active.Path);
        healthChecks.Active.Query = string.IsNullOrWhiteSpace(healthChecks.Active.Query)
            ? null
            : healthChecks.Active.Query.Trim();
    }

    private static void NormalizeDestinations(IReadOnlyList<GatewayDestinationOptions>? destinations)
    {
        if (destinations is null)
        {
            return;
        }

        foreach (GatewayDestinationOptions destination in destinations)
        {
            destination.Name = destination.Name.Trim();
            destination.Address = destination.Address.Trim();
            destination.Health = string.IsNullOrWhiteSpace(destination.Health)
                ? null
                : destination.Health.Trim();
        }
    }

    public static void Validate(CryptoApiGatewayOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ServiceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ClusterId);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ApiBasePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.CorrelationIdHeaderName);

        if (!options.ApiBasePath.StartsWith("/", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Crypto API gateway base path must start with '/'.");
        }

        if (options.HttpClient.ActivityTimeoutSeconds <= 0)
        {
            throw new InvalidOperationException("Crypto API gateway upstream activity timeout must be greater than zero seconds.");
        }

        if (options.MaxRequestBodySizeBytes is <= 0)
        {
            throw new InvalidOperationException("Crypto API gateway request body limit must be greater than zero when configured.");
        }

        if (options.HealthChecks.Active.Enabled)
        {
            if (options.HealthChecks.Active.IntervalSeconds <= 0)
            {
                throw new InvalidOperationException("Crypto API gateway active health-check interval must be greater than zero seconds.");
            }

            if (options.HealthChecks.Active.TimeoutSeconds <= 0)
            {
                throw new InvalidOperationException("Crypto API gateway active health-check timeout must be greater than zero seconds.");
            }

            if (options.HealthChecks.Active.ConsecutiveFailuresThreshold <= 0)
            {
                throw new InvalidOperationException("Crypto API gateway active health-check threshold must be greater than zero.");
            }
        }

        List<GatewayDestinationOptions> enabledDestinations = options.Destinations
            .Where(static destination => destination.Enabled)
            .ToList();

        if (enabledDestinations.Count == 0)
        {
            throw new InvalidOperationException("Configure at least one enabled CryptoApiGateway destination.");
        }

        HashSet<string> seenNames = new(StringComparer.OrdinalIgnoreCase);
        foreach (GatewayDestinationOptions destination in enabledDestinations)
        {
            if (string.IsNullOrWhiteSpace(destination.Name))
            {
                throw new InvalidOperationException("Each enabled CryptoApiGateway destination must define a non-empty Name.");
            }

            if (!seenNames.Add(destination.Name))
            {
                throw new InvalidOperationException($"Duplicate CryptoApiGateway destination name '{destination.Name}' is not allowed.");
            }

            ValidateAbsoluteUri(destination.Address, $"Destination '{destination.Name}' address");
            if (destination.Health is not null)
            {
                ValidateAbsoluteUri(destination.Health, $"Destination '{destination.Name}' health address");
            }
        }
    }

    private static void ValidateAbsoluteUri(string candidate, string description)
    {
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture, $"{description} must be an absolute http/https URI."));
        }
    }
}
