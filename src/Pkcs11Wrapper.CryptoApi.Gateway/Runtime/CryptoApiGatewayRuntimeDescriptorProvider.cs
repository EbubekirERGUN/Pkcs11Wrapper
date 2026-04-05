using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Gateway.Configuration;

namespace Pkcs11Wrapper.CryptoApi.Gateway.Runtime;

public sealed class CryptoApiGatewayRuntimeDescriptorProvider(
    IOptions<CryptoApiGatewayOptions> options,
    TimeProvider timeProvider)
{
    private readonly string _instanceId = Guid.NewGuid().ToString("N");
    private readonly DateTimeOffset _startedAtUtc = timeProvider.GetUtcNow();

    public CryptoApiGatewayRuntimeDescriptor Describe()
    {
        CryptoApiGatewayOptions gatewayOptions = options.Value;
        int configuredDestinationCount = gatewayOptions.Destinations.Count(static destination => destination.Enabled);

        return new CryptoApiGatewayRuntimeDescriptor(
            ServiceName: gatewayOptions.ServiceName,
            InstanceId: _instanceId,
            ClusterId: gatewayOptions.ClusterId,
            ApiBasePath: gatewayOptions.ApiBasePath,
            DeploymentModel: "gateway-fronted stateless Crypto API fleet",
            LoadBalancingPolicy: gatewayOptions.LoadBalancingPolicy,
            CorrelationIdHeaderName: gatewayOptions.CorrelationIdHeaderName,
            MaxRequestBodySizeBytes: gatewayOptions.MaxRequestBodySizeBytes,
            ActiveHealthChecksEnabled: gatewayOptions.HealthChecks.Active.Enabled,
            ConfiguredDestinationCount: configuredDestinationCount,
            StartedAtUtc: _startedAtUtc,
            CurrentSurface:
            [
                "GET /",
                $"GET {CryptoApiGatewayDefaults.RuntimePath}",
                $"GET {CryptoApiGatewayDefaults.HealthLivePath}",
                $"GET {CryptoApiGatewayDefaults.HealthReadyPath}",
                $"ANY {gatewayOptions.ApiBasePath}",
                $"ANY {gatewayOptions.ApiBasePath}/{{**catch-all}}"
            ],
            Notes:
            [
                "YARP fronts multiple stateless Crypto API instances behind one ingress endpoint.",
                "Active health checks remove unhealthy destinations from load-balanced selection.",
                "The gateway preserves or creates a correlation id header and mirrors it on responses.",
                "This slice intentionally avoids becoming a standalone auth product; Crypto API auth still happens upstream in the API hosts."
            ]);
    }
}
