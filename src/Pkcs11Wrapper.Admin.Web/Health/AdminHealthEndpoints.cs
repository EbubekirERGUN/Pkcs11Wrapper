using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Pkcs11Wrapper.Admin.Web.Health;

public static class AdminHealthEndpoints
{
    public static Task<IResult> LiveAsync(HealthCheckService healthChecks, CancellationToken cancellationToken)
        => ExecuteAsync(healthChecks, static _ => false, cancellationToken);

    public static Task<IResult> ReadyAsync(HealthCheckService healthChecks, CancellationToken cancellationToken)
        => ExecuteAsync(
            healthChecks,
            static registration => registration.Tags.Contains("ready", StringComparer.Ordinal),
            cancellationToken);

    private static async Task<IResult> ExecuteAsync(
        HealthCheckService healthChecks,
        Func<HealthCheckRegistration, bool> predicate,
        CancellationToken cancellationToken)
    {
        HealthReport report = await healthChecks.CheckHealthAsync(predicate, cancellationToken);
        int statusCode = report.Status == HealthStatus.Unhealthy
            ? StatusCodes.Status503ServiceUnavailable
            : StatusCodes.Status200OK;

        return Results.Json(AdminHealthResponse.FromReport(report), statusCode: statusCode);
    }
}
