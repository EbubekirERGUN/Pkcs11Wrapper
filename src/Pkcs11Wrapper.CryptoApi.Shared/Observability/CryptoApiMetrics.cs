using System.Diagnostics;
using System.Diagnostics.Metrics;
using Pkcs11Wrapper.CryptoApi.Caching;

namespace Pkcs11Wrapper.CryptoApi.Observability;

public interface ICryptoApiSharedStateMetricsSource
{
    CryptoApiSharedStateMetricsSnapshot GetMetricsSnapshot();
}

public interface ICryptoApiPkcs11RuntimeMetricsSource
{
    IReadOnlyList<CryptoApiPkcs11SessionPoolMetricsSnapshot> GetSessionPoolMetricsSnapshots();
}

public sealed record CryptoApiRequestPathCacheMetricsSnapshot(
    bool Enabled,
    int AuthenticationEntryCount,
    int AuthenticationEntryLimit,
    int AuthorizationEntryCount,
    int AuthorizationEntryLimit);

public sealed record CryptoApiSharedStateMetricsSnapshot(
    bool Configured,
    string Provider,
    int EffectiveMaxPoolSize);

public sealed record CryptoApiPkcs11SessionPoolMetricsSnapshot(
    string Backend,
    ulong SlotId,
    int IdleSessions,
    int InUseSessions,
    int MaxRetainedSessions);

public sealed class CryptoApiMetrics : IDisposable
{
    public const string MeterName = "Pkcs11Wrapper.CryptoApi";

    private readonly Meter _meter = new(MeterName);
    private readonly Counter<long> _authenticationResults;
    private readonly Counter<long> _authorizationResults;
    private readonly Counter<long> _requestPathCacheLookups;
    private readonly Counter<long> _distributedCacheRequests;
    private readonly Histogram<double> _distributedCacheRequestDuration;
    private readonly Counter<long> _sharedStateRequests;
    private readonly Histogram<double> _sharedStateRequestDuration;
    private readonly Counter<long> _sharedStateDatabaseReads;
    private readonly Counter<long> _lastUsedRefreshEvents;
    private readonly Counter<long> _rateLimitRejections;
    private readonly Counter<long> _pkcs11Operations;
    private readonly Histogram<double> _pkcs11OperationDuration;
    private readonly Counter<long> _pkcs11SessionLeases;
    private readonly Counter<long> _pkcs11SessionReturns;
    private readonly ObservableGauge<int> _authenticationCacheEntries;
    private readonly ObservableGauge<double> _authenticationCacheUtilization;
    private readonly ObservableGauge<int> _authorizationCacheEntries;
    private readonly ObservableGauge<double> _authorizationCacheUtilization;
    private readonly ObservableGauge<int> _sharedStatePoolMaxConnections;
    private readonly ObservableGauge<int> _pkcs11SessionsIdle;
    private readonly ObservableGauge<int> _pkcs11SessionsInUse;
    private readonly ObservableGauge<int> _pkcs11SessionsMaxRetained;

    private CryptoApiRequestPathCache? _requestPathCache;
    private ICryptoApiSharedStateMetricsSource? _sharedStateMetricsSource;
    private ICryptoApiPkcs11RuntimeMetricsSource? _pkcs11RuntimeMetricsSource;

    public CryptoApiMetrics()
    {
        _authenticationResults = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_authentication_results_total");
        _authorizationResults = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_authorization_results_total");
        _requestPathCacheLookups = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_request_path_cache_lookups_total");
        _distributedCacheRequests = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_distributed_cache_requests_total");
        _distributedCacheRequestDuration = _meter.CreateHistogram<double>("pkcs11wrapper_crypto_api_distributed_cache_request_duration_seconds", unit: "s");
        _sharedStateRequests = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_shared_state_requests_total");
        _sharedStateRequestDuration = _meter.CreateHistogram<double>("pkcs11wrapper_crypto_api_shared_state_request_duration_seconds", unit: "s");
        _sharedStateDatabaseReads = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_shared_state_database_reads_total");
        _lastUsedRefreshEvents = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_last_used_refresh_events_total");
        _rateLimitRejections = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_rate_limit_rejections_total");
        _pkcs11Operations = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_pkcs11_operations_total");
        _pkcs11OperationDuration = _meter.CreateHistogram<double>("pkcs11wrapper_crypto_api_pkcs11_operation_duration_seconds", unit: "s");
        _pkcs11SessionLeases = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_pkcs11_session_leases_total");
        _pkcs11SessionReturns = _meter.CreateCounter<long>("pkcs11wrapper_crypto_api_pkcs11_session_returns_total");

        _authenticationCacheEntries = _meter.CreateObservableGauge<int>(
            "pkcs11wrapper_crypto_api_authentication_cache_entries",
            ObserveAuthenticationCacheEntries);
        _authenticationCacheUtilization = _meter.CreateObservableGauge<double>(
            "pkcs11wrapper_crypto_api_authentication_cache_utilization_ratio",
            ObserveAuthenticationCacheUtilization);
        _authorizationCacheEntries = _meter.CreateObservableGauge<int>(
            "pkcs11wrapper_crypto_api_authorization_cache_entries",
            ObserveAuthorizationCacheEntries);
        _authorizationCacheUtilization = _meter.CreateObservableGauge<double>(
            "pkcs11wrapper_crypto_api_authorization_cache_utilization_ratio",
            ObserveAuthorizationCacheUtilization);
        _sharedStatePoolMaxConnections = _meter.CreateObservableGauge<int>(
            "pkcs11wrapper_crypto_api_shared_state_pool_max_connections",
            ObserveSharedStatePoolMaxConnections);
        _pkcs11SessionsIdle = _meter.CreateObservableGauge<int>(
            "pkcs11wrapper_crypto_api_pkcs11_sessions_idle",
            ObservePkcs11IdleSessions);
        _pkcs11SessionsInUse = _meter.CreateObservableGauge<int>(
            "pkcs11wrapper_crypto_api_pkcs11_sessions_in_use",
            ObservePkcs11InUseSessions);
        _pkcs11SessionsMaxRetained = _meter.CreateObservableGauge<int>(
            "pkcs11wrapper_crypto_api_pkcs11_sessions_max_retained",
            ObservePkcs11MaxRetainedSessions);
    }

    public void RegisterRequestPathCache(CryptoApiRequestPathCache requestPathCache)
        => _requestPathCache = requestPathCache;

    public void RegisterSharedStateSource(ICryptoApiSharedStateMetricsSource sharedStateMetricsSource)
        => _sharedStateMetricsSource = sharedStateMetricsSource;

    public void RegisterRuntimeSource(ICryptoApiPkcs11RuntimeMetricsSource runtimeMetricsSource)
        => _pkcs11RuntimeMetricsSource = runtimeMetricsSource;

    public void RecordAuthenticationResult(string result, string source)
        => _authenticationResults.Add(1, CreateTags(("result", result), ("source", source)));

    public void RecordAuthorizationResult(string result, string source)
        => _authorizationResults.Add(1, CreateTags(("result", result), ("source", source)));

    public void RecordRequestPathCacheLookup(string cache, string layer, string result)
        => _requestPathCacheLookups.Add(1, CreateTags(("cache", cache), ("layer", layer), ("result", result)));

    public void RecordDistributedCacheRequest(string operation, string result, TimeSpan duration)
    {
        TagList tags = CreateTags(("operation", operation), ("result", result));
        _distributedCacheRequests.Add(1, tags);
        _distributedCacheRequestDuration.Record(duration.TotalSeconds, tags);
    }

    public void RecordSharedStateRequest(string operation, string result, TimeSpan duration)
    {
        TagList tags = CreateTags(("operation", operation), ("result", result));
        _sharedStateRequests.Add(1, tags);
        _sharedStateRequestDuration.Record(duration.TotalSeconds, tags);
    }

    public void RecordSharedStateDatabaseRead(string operation)
        => _sharedStateDatabaseReads.Add(1, CreateTags(("operation", operation)));

    public void RecordLastUsedRefreshEvent(string path, string stage, string result)
        => _lastUsedRefreshEvents.Add(1, CreateTags(("path", path), ("stage", stage), ("result", result)));

    public void RecordRateLimitRejection(string scope)
        => _rateLimitRejections.Add(1, CreateTags(("scope", scope)));

    public void RecordPkcs11Operation(string operation, string algorithm, string backend, string result, TimeSpan duration)
    {
        TagList tags = CreateTags(("operation", operation), ("algorithm", algorithm), ("backend", backend), ("result", result));
        _pkcs11Operations.Add(1, tags);
        _pkcs11OperationDuration.Record(duration.TotalSeconds, tags);
    }

    public void RecordPkcs11SessionLease(string backend, ulong slotId, string result)
        => _pkcs11SessionLeases.Add(1, CreateTags(("backend", backend), ("slot", slotId.ToString(System.Globalization.CultureInfo.InvariantCulture)), ("result", result)));

    public void RecordPkcs11SessionReturn(string backend, ulong slotId, string result)
        => _pkcs11SessionReturns.Add(1, CreateTags(("backend", backend), ("slot", slotId.ToString(System.Globalization.CultureInfo.InvariantCulture)), ("result", result)));

    public void Dispose() => _meter.Dispose();

    private IEnumerable<Measurement<int>> ObserveAuthenticationCacheEntries()
    {
        CryptoApiRequestPathCacheMetricsSnapshot? snapshot = _requestPathCache?.GetMetricsSnapshot();
        if (snapshot is null)
        {
            return [];
        }

        return [new Measurement<int>(snapshot.AuthenticationEntryCount)];
    }

    private IEnumerable<Measurement<double>> ObserveAuthenticationCacheUtilization()
    {
        CryptoApiRequestPathCacheMetricsSnapshot? snapshot = _requestPathCache?.GetMetricsSnapshot();
        if (snapshot is null)
        {
            return [];
        }

        double utilization = snapshot.AuthenticationEntryLimit <= 0
            ? 0
            : (double)snapshot.AuthenticationEntryCount / snapshot.AuthenticationEntryLimit;
        return [new Measurement<double>(utilization)];
    }

    private IEnumerable<Measurement<int>> ObserveAuthorizationCacheEntries()
    {
        CryptoApiRequestPathCacheMetricsSnapshot? snapshot = _requestPathCache?.GetMetricsSnapshot();
        if (snapshot is null)
        {
            return [];
        }

        return [new Measurement<int>(snapshot.AuthorizationEntryCount)];
    }

    private IEnumerable<Measurement<double>> ObserveAuthorizationCacheUtilization()
    {
        CryptoApiRequestPathCacheMetricsSnapshot? snapshot = _requestPathCache?.GetMetricsSnapshot();
        if (snapshot is null)
        {
            return [];
        }

        double utilization = snapshot.AuthorizationEntryLimit <= 0
            ? 0
            : (double)snapshot.AuthorizationEntryCount / snapshot.AuthorizationEntryLimit;
        return [new Measurement<double>(utilization)];
    }

    private IEnumerable<Measurement<int>> ObserveSharedStatePoolMaxConnections()
    {
        CryptoApiSharedStateMetricsSnapshot? snapshot = _sharedStateMetricsSource?.GetMetricsSnapshot();
        if (snapshot is null || !snapshot.Configured)
        {
            return [];
        }

        return [new Measurement<int>(snapshot.EffectiveMaxPoolSize, CreateTags(("provider", snapshot.Provider)))];
    }

    private IEnumerable<Measurement<int>> ObservePkcs11IdleSessions()
        => ObservePkcs11Sessions(static snapshot => snapshot.IdleSessions);

    private IEnumerable<Measurement<int>> ObservePkcs11InUseSessions()
        => ObservePkcs11Sessions(static snapshot => snapshot.InUseSessions);

    private IEnumerable<Measurement<int>> ObservePkcs11MaxRetainedSessions()
        => ObservePkcs11Sessions(static snapshot => snapshot.MaxRetainedSessions);

    private IEnumerable<Measurement<int>> ObservePkcs11Sessions(Func<CryptoApiPkcs11SessionPoolMetricsSnapshot, int> selector)
    {
        IReadOnlyList<CryptoApiPkcs11SessionPoolMetricsSnapshot>? snapshots = _pkcs11RuntimeMetricsSource?.GetSessionPoolMetricsSnapshots();
        if (snapshots is null || snapshots.Count == 0)
        {
            return [];
        }

        List<Measurement<int>> measurements = new(snapshots.Count);
        foreach (CryptoApiPkcs11SessionPoolMetricsSnapshot snapshot in snapshots)
        {
            measurements.Add(new Measurement<int>(
                selector(snapshot),
                CreateTags(
                    ("backend", snapshot.Backend),
                    ("slot", snapshot.SlotId.ToString(System.Globalization.CultureInfo.InvariantCulture)))));
        }

        return measurements;
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
