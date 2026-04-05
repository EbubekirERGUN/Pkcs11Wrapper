using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Yarp.ReverseProxy.Configuration;

namespace Pkcs11Wrapper.CryptoApi.Gateway.Configuration;

public sealed class CryptoApiGatewayProxyConfigProvider(IOptions<CryptoApiGatewayOptions> options) : IProxyConfigProvider
{
    private readonly IProxyConfig _config = new StaticProxyConfig(
        CryptoApiGatewayProxyConfigBuilder.BuildRoutes(options.Value),
        CryptoApiGatewayProxyConfigBuilder.BuildClusters(options.Value));

    public IProxyConfig GetConfig() => _config;

    private sealed class StaticProxyConfig : IProxyConfig
    {
        private readonly CancellationTokenSource _changeTokenSource = new();

        public StaticProxyConfig(IReadOnlyList<RouteConfig> routes, IReadOnlyList<ClusterConfig> clusters)
        {
            Routes = routes;
            Clusters = clusters;
            ChangeToken = new CancellationChangeToken(_changeTokenSource.Token);
        }

        public IReadOnlyList<RouteConfig> Routes { get; }

        public IReadOnlyList<ClusterConfig> Clusters { get; }

        public IChangeToken ChangeToken { get; }
    }
}
