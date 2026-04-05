using System.Diagnostics;
using System.Diagnostics.Metrics;
using Pkcs11Wrapper.CryptoApi.Gateway.Health;

namespace Pkcs11Wrapper.CryptoApi.Gateway.Observability;

public sealed class GatewayMetrics : IDisposable
{
    public const string MeterName = "Pkcs11Wrapper.CryptoApi.Gateway";

    private readonly Meter _meter = new(MeterName);
    private readonly Counter<long> _backendReadinessProbes;
    private readonly Histogram<double> _backendReadinessProbeDuration;
    private readonly Counter<long> _requestBodyRejections;
    private readonly ObservableGauge<int> _healthyDestinations;
    private readonly ObservableGauge<int> _configuredDestinations;
    private GatewayBackendReadinessResult? _lastReadinessResult;

    public GatewayMetrics()
    {
        _backendReadinessProbes = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_gateway_backend_readiness_probes_total");
        _backendReadinessProbeDuration = _meter.CreateHistogram<double>("pkcs11wrapper_crypto_api_gateway_backend_readiness_probe_duration_seconds", unit: "s");
        _requestBodyRejections = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_gateway_request_body_rejections_total");
        _healthyDestinations = _meter.CreateObservableGauge<int>("pkcs11wrapper_crypto_api_gateway_healthy_destinations", ObserveHealthyDestinations);
        _configuredDestinations = _meter.CreateObservableGauge<int>("pkcs11wrapper_crypto_api_gateway_configured_destinations", ObserveConfiguredDestinations);
    }

    public void RecordBackendReadinessProbe(GatewayBackendReadinessResult result, TimeSpan duration)
    {
        ArgumentNullException.ThrowIfNull(result);

        _lastReadinessResult = result;
        TagList tags = CreateTags(
            ("result", result.Ready ? "ready" : "not_ready"),
            ("cluster", result.ClusterId));
        _backendReadinessProbes.Add(1, tags);
        _backendReadinessProbeDuration.Record(duration.TotalSeconds, tags);
    }

    public void RecordRequestBodyRejected(long maxRequestBodySizeBytes)
        => _requestBodyRejections.Add(1, CreateTags(("max_request_body_size_bytes", maxRequestBodySizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture))));

    public void Dispose() => _meter.Dispose();

    private IEnumerable<Measurement<int>> ObserveHealthyDestinations()
    {
        GatewayBackendReadinessResult? result = _lastReadinessResult;
        if (result is null)
        {
            return [];
        }

        return [new Measurement<int>(result.HealthyDestinationCount, CreateTags(("cluster", result.ClusterId)))];
    }

    private IEnumerable<Measurement<int>> ObserveConfiguredDestinations()
    {
        GatewayBackendReadinessResult? result = _lastReadinessResult;
        if (result is null)
        {
            return [];
        }

        return [new Measurement<int>(result.ConfiguredDestinationCount, CreateTags(("cluster", result.ClusterId)))];
    }

    private static TagList CreateTags(params (string Key, string? Value)[] pairs)
    {
        TagList tags = new();
        foreach ((string key, string? value) in pairs)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                tags.Add(key, value);
            }
        }

        return tags;
    }
}
