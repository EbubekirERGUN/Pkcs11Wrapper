using System.Net;
using Pkcs11Wrapper.Admin.Web.Configuration;

namespace Pkcs11Wrapper.Admin.Web.Health;

public static class AdminContainerHealthProbe
{
    private const string HealthCheckArgument = "--container-healthcheck";

    public static async Task<bool> TryExecuteAsync(string[] args, CancellationToken cancellationToken = default)
    {
        if (!args.Any(argument => string.Equals(argument, HealthCheckArgument, StringComparison.Ordinal)))
        {
            return false;
        }

        string probeUrl = ResolveProbeUrl(args);

        try
        {
            using HttpClient client = new()
            {
                Timeout = TimeSpan.FromSeconds(5)
            };

            using HttpResponseMessage response = await client.GetAsync(probeUrl, cancellationToken);
            Environment.ExitCode = response.StatusCode == HttpStatusCode.OK ? 0 : 1;
            return true;
        }
        catch
        {
            Environment.ExitCode = 1;
            return true;
        }
    }

    private static string ResolveProbeUrl(IReadOnlyList<string> args)
    {
        int index = args
            .Select((value, position) => new { value, position })
            .First(candidate => string.Equals(candidate.value, HealthCheckArgument, StringComparison.Ordinal))
            .position;

        if (index + 1 < args.Count)
        {
            string candidate = args[index + 1].Trim();
            if (!string.IsNullOrWhiteSpace(candidate) && !candidate.StartsWith("--", StringComparison.Ordinal))
            {
                return candidate;
            }
        }

        return AdminHostDefaults.DefaultContainerHealthCheckUrl;
    }
}
