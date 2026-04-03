using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Pkcs11Wrapper.Admin.Web.Health;

public sealed record AdminHealthResponse(
    string Status,
    double TotalDurationMs,
    IReadOnlyDictionary<string, AdminHealthCheckResponse> Checks)
{
    public static AdminHealthResponse FromReport(HealthReport report)
        => new(
            report.Status.ToString(),
            report.TotalDuration.TotalMilliseconds,
            report.Entries.ToDictionary(
                static entry => entry.Key,
                static entry => new AdminHealthCheckResponse(
                    entry.Value.Status.ToString(),
                    entry.Value.Description,
                    entry.Value.Duration.TotalMilliseconds)));
}

public sealed record AdminHealthCheckResponse(
    string Status,
    string? Description,
    double DurationMs);
