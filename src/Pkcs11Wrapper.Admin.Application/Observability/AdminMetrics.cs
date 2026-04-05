using System.Diagnostics;
using System.Diagnostics.Metrics;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Application.Observability;

public sealed class AdminMetrics : IDisposable
{
    public const string MeterName = "Pkcs11Wrapper.Admin";

    private readonly Meter _meter = new(MeterName);
    private readonly Counter<long> _loginAttempts;
    private readonly Counter<long> _logouts;
    private readonly ObservableGauge<int> _sessions;
    private AdminSessionRegistry? _sessionRegistry;

    public AdminMetrics()
    {
        _loginAttempts = _meter.CreateCounter<long>("pkcs11wrapper_admin_login_attempts_total");
        _logouts = _meter.CreateCounter<long>("pkcs11wrapper_admin_logouts_total");
        _sessions = _meter.CreateObservableGauge<int>("pkcs11wrapper_admin_sessions", ObserveSessions);
    }

    public void RegisterSessionRegistry(AdminSessionRegistry sessionRegistry)
        => _sessionRegistry = sessionRegistry;

    public void RecordLoginAttempt(string result)
        => _loginAttempts.Add(1, CreateTags(("result", result)));

    public void RecordLogout(string result)
        => _logouts.Add(1, CreateTags(("result", result)));

    public void Dispose() => _meter.Dispose();

    private IEnumerable<Measurement<int>> ObserveSessions()
    {
        AdminSessionRegistry.AdminSessionRegistryMetricsSnapshot? snapshot = _sessionRegistry?.GetMetricsSnapshot();
        if (snapshot is null)
        {
            return [];
        }

        return
        [
            new Measurement<int>(snapshot.Healthy, CreateTags(("status", "healthy"))),
            new Measurement<int>(snapshot.Broken, CreateTags(("status", "broken"))),
            new Measurement<int>(snapshot.Expired, CreateTags(("status", "expired"))),
            new Measurement<int>(snapshot.Invalidated, CreateTags(("status", "invalidated")))
        ];
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
