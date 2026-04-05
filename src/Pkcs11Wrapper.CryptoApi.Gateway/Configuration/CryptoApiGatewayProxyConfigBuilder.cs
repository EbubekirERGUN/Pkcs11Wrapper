using System.Globalization;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Health;
using Yarp.ReverseProxy.LoadBalancing;

namespace Pkcs11Wrapper.CryptoApi.Gateway.Configuration;

public static class CryptoApiGatewayProxyConfigBuilder
{
    public static IReadOnlyList<RouteConfig> BuildRoutes(CryptoApiGatewayOptions options)
    {
        string basePath = CryptoApiGatewayDefaults.NormalizeBasePath(options.ApiBasePath);

        return
        [
            new RouteConfig
            {
                RouteId = "crypto-api-root",
                ClusterId = options.ClusterId,
                Match = new RouteMatch
                {
                    Path = basePath
                }
            },
            new RouteConfig
            {
                RouteId = "crypto-api-catch-all",
                ClusterId = options.ClusterId,
                Match = new RouteMatch
                {
                    Path = $"{basePath}/{{**catch-all}}"
                }
            }
        ];
    }

    public static IReadOnlyList<ClusterConfig> BuildClusters(CryptoApiGatewayOptions options)
    {
        Dictionary<string, DestinationConfig> destinations = options.Destinations
            .Where(static destination => destination.Enabled)
            .ToDictionary(
                static destination => destination.Name,
                static destination => new DestinationConfig
                {
                    Address = CryptoApiGatewayDefaults.NormalizeDestinationAddress(destination.Address),
                    Health = destination.Health is null ? null : CryptoApiGatewayDefaults.NormalizeDestinationAddress(destination.Health)
                },
                StringComparer.OrdinalIgnoreCase);

        Dictionary<string, string> metadata = new(StringComparer.OrdinalIgnoreCase)
        {
            [ConsecutiveFailuresHealthPolicyOptions.ThresholdMetadataName] = options.HealthChecks.Active.ConsecutiveFailuresThreshold.ToString(CultureInfo.InvariantCulture)
        };

        return
        [
            new ClusterConfig
            {
                ClusterId = options.ClusterId,
                LoadBalancingPolicy = string.IsNullOrWhiteSpace(options.LoadBalancingPolicy)
                    ? LoadBalancingPolicies.RoundRobin
                    : options.LoadBalancingPolicy,
                Destinations = destinations,
                Metadata = metadata,
                HealthCheck = new HealthCheckConfig
                {
                    Active = new ActiveHealthCheckConfig
                    {
                        Enabled = options.HealthChecks.Active.Enabled,
                        Interval = TimeSpan.FromSeconds(options.HealthChecks.Active.IntervalSeconds),
                        Timeout = TimeSpan.FromSeconds(options.HealthChecks.Active.TimeoutSeconds),
                        Policy = HealthCheckConstants.ActivePolicy.ConsecutiveFailures,
                        Path = options.HealthChecks.Active.Path,
                        Query = options.HealthChecks.Active.Query
                    }
                },
                HttpClient = new HttpClientConfig
                {
                    DangerousAcceptAnyServerCertificate = options.HttpClient.DangerousAcceptAnyServerCertificate
                },
                HttpRequest = new ForwarderRequestConfig
                {
                    ActivityTimeout = TimeSpan.FromSeconds(options.HttpClient.ActivityTimeoutSeconds)
                }
            }
        ];
    }
}
