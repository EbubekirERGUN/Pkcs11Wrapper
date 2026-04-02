using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Pkcs11Wrapper.Admin.Web.Health;

public static class AdminHealthResponseWriter
{
    public static Task WriteAsync(HttpContext context, HealthReport report)
    {
        context.Response.ContentType = "application/json";

        AdminHealthResponse payload = new(
            report.Status.ToString(),
            report.TotalDuration.TotalMilliseconds,
            report.Entries.ToDictionary(
                static entry => entry.Key,
                static entry => new AdminHealthCheckResponse(
                    entry.Value.Status.ToString(),
                    entry.Value.Description,
                    entry.Value.Duration.TotalMilliseconds)));

        return context.Response.WriteAsync(JsonSerializer.Serialize(payload));
    }

    private sealed record AdminHealthResponse(
        string Status,
        double TotalDurationMs,
        IReadOnlyDictionary<string, AdminHealthCheckResponse> Checks);

    private sealed record AdminHealthCheckResponse(
        string Status,
        string? Description,
        double DurationMs);
}
