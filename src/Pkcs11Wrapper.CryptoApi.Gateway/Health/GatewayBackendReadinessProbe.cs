using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Gateway.Configuration;

namespace Pkcs11Wrapper.CryptoApi.Gateway.Health;

public sealed class GatewayBackendReadinessProbe(
    IHttpClientFactory httpClientFactory,
    IOptions<CryptoApiGatewayOptions> options)
{
    public const string HttpClientName = "GatewayBackendReadinessProbe";

    public async Task<GatewayBackendReadinessResult> ProbeAsync(CancellationToken cancellationToken)
    {
        CryptoApiGatewayOptions gatewayOptions = options.Value;
        List<GatewayDestinationProbeResult> destinationResults = [];
        int healthyDestinationCount = 0;

        using HttpClient httpClient = httpClientFactory.CreateClient(HttpClientName);
        httpClient.Timeout = TimeSpan.FromSeconds(Math.Max(1, gatewayOptions.HealthChecks.Active.TimeoutSeconds));

        foreach (GatewayDestinationOptions destination in gatewayOptions.Destinations.Where(static destination => destination.Enabled))
        {
            string probeUrl = BuildProbeUrl(destination, gatewayOptions.HealthChecks.Active.Path, gatewayOptions.HealthChecks.Active.Query);
            GatewayDestinationProbeResult result;

            try
            {
                using HttpResponseMessage response = await httpClient.GetAsync(probeUrl, cancellationToken);
                bool healthy = (int)response.StatusCode is >= 200 and < 300;
                if (healthy)
                {
                    healthyDestinationCount++;
                }

                result = new GatewayDestinationProbeResult(
                    destination.Name,
                    destination.Address,
                    probeUrl,
                    healthy,
                    (int)response.StatusCode,
                    null);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                result = new GatewayDestinationProbeResult(
                    destination.Name,
                    destination.Address,
                    probeUrl,
                    false,
                    null,
                    ex.Message);
            }

            destinationResults.Add(result);
        }

        return new GatewayBackendReadinessResult(
            gatewayOptions.ServiceName,
            gatewayOptions.ClusterId,
            healthyDestinationCount > 0,
            healthyDestinationCount,
            destinationResults.Count,
            destinationResults,
            DateTimeOffset.UtcNow);
    }

    private static string BuildProbeUrl(GatewayDestinationOptions destination, string healthPath, string? query)
    {
        string baseUrl = destination.Health ?? destination.Address;
        Uri baseUri = new(CryptoApiGatewayDefaults.NormalizeDestinationAddress(baseUrl), UriKind.Absolute);
        string normalizedPath = CryptoApiGatewayDefaults.NormalizeBasePath(healthPath);
        UriBuilder uriBuilder = new(new Uri(baseUri, normalizedPath));

        if (!string.IsNullOrWhiteSpace(query))
        {
            uriBuilder.Query = query.TrimStart('?');
        }

        return uriBuilder.Uri.ToString();
    }
}

public sealed record GatewayBackendReadinessResult(
    string ServiceName,
    string ClusterId,
    bool Ready,
    int HealthyDestinationCount,
    int ConfiguredDestinationCount,
    IReadOnlyList<GatewayDestinationProbeResult> Destinations,
    DateTimeOffset ProbedAtUtc);

public sealed record GatewayDestinationProbeResult(
    string Name,
    string Address,
    string ProbeUrl,
    bool Healthy,
    int? StatusCode,
    string? Error);
