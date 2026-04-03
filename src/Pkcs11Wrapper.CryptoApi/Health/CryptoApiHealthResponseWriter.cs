using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Pkcs11Wrapper.CryptoApi.Health;

public static class CryptoApiHealthResponseWriter
{
    public static Task WriteAsync(HttpContext context, HealthReport report)
    {
        context.Response.ContentType = "application/json";

        CryptoApiHealthResponse payload = new(
            report.Status.ToString(),
            report.TotalDuration.TotalMilliseconds,
            report.Entries.ToDictionary(
                static entry => entry.Key,
                static entry => new CryptoApiHealthCheckResponse(
                    entry.Value.Status.ToString(),
                    entry.Value.Description,
                    entry.Value.Duration.TotalMilliseconds)));

        return context.Response.WriteAsync(JsonSerializer.Serialize(payload));
    }

    private sealed record CryptoApiHealthResponse(
        string Status,
        double TotalDurationMs,
        IReadOnlyDictionary<string, CryptoApiHealthCheckResponse> Checks);

    private sealed record CryptoApiHealthCheckResponse(
        string Status,
        string? Description,
        double DurationMs);
}
