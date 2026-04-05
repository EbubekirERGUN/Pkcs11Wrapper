using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Pkcs11Wrapper.CryptoApiPerf;

internal static class CryptoApiPerfSummaryWriter
{
    public static void Write(CryptoApiPerfOptions options, IReadOnlyList<CryptoApiPerfResult> results)
    {
        Directory.CreateDirectory(options.ResultsRoot);

        CryptoApiPerfResult[] normalizedResults = results
            .Select(result => result with
            {
                TargetBaseUrl = NormalizeDisplayUrl(
                    result.TargetBaseUrl,
                    result.Topology == "single-instance" ? "single-instance-direct" : "multi-instance-gateway")
            })
            .OrderBy(static result => result.Name, StringComparer.Ordinal)
            .ToArray();

        CryptoApiPerfSummaryDocument document = new(
            GeneratedUtc: DateTimeOffset.UtcNow,
            ProfileName: options.ProfileName,
            WarmUpDurationSeconds: options.WarmUpDuration.TotalSeconds,
            BombingDurationSeconds: options.BombingDuration.TotalSeconds,
            SingleInstanceCopies: options.SingleInstanceCopies,
            MultiInstanceCopies: options.MultiInstanceCopies,
            HostFramework: RuntimeInformation.FrameworkDescription,
            OperatingSystem: RuntimeInformation.OSDescription,
            Architecture: RuntimeInformation.ProcessArchitecture.ToString(),
            SdkVersion: Environment.GetEnvironmentVariable("PKCS11_CRYPTO_API_PERF_SDK_VERSION") ?? "unknown",
            RuntimeVersion: Environment.GetEnvironmentVariable("PKCS11_CRYPTO_API_PERF_RUNTIME_VERSION") ?? "unknown",
            ModulePath: options.ModulePath,
            TokenLabel: options.TokenLabel,
            SingleBaseUrl: NormalizeDisplayUrl(options.SingleBaseUrl, "single-instance-direct"),
            MultiBaseUrl: NormalizeDisplayUrl(options.MultiBaseUrl, "multi-instance-gateway"),
            Results: normalizedResults);

        string markdown = BuildMarkdown(document, TryLoadBaseline(options));
        string json = JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
        UTF8Encoding utf8 = new(encoderShouldEmitUTF8Identifier: false);

        File.WriteAllText(Path.Combine(options.ResultsRoot, "summary.md"), markdown, utf8);
        File.WriteAllText(Path.Combine(options.ResultsRoot, "summary.json"), json, utf8);

        if (!string.IsNullOrWhiteSpace(options.CanonicalMarkdownPath))
        {
            WriteCanonical(options.CanonicalMarkdownPath!, BuildMarkdown(document, baseline: null), utf8);
        }

        if (!string.IsNullOrWhiteSpace(options.CanonicalJsonPath))
        {
            WriteCanonical(options.CanonicalJsonPath!, json, utf8);
        }
    }

    private static string NormalizeDisplayUrl(string url, string loopbackLabel)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri))
        {
            return url;
        }

        if (uri.IsLoopback)
        {
            return loopbackLabel;
        }

        return url;
    }

    private static void WriteCanonical(string path, string content, Encoding encoding)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content, encoding);
    }

    private static CryptoApiPerfSummaryDocument? TryLoadBaseline(CryptoApiPerfOptions options)
    {
        string? path = options.CanonicalJsonPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            string repoRoot = Environment.GetEnvironmentVariable("PKCS11_CRYPTO_API_PERF_REPO_ROOT")
                ?? ResolveRepoRoot();
            path = Path.Combine(repoRoot, "docs", "crypto-api-performance", "latest-linux-softhsm.json");
            if (!File.Exists(path))
            {
                return null;
            }
        }

        try
        {
            return JsonSerializer.Deserialize<CryptoApiPerfSummaryDocument>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }

    private static string BuildMarkdown(CryptoApiPerfSummaryDocument document, CryptoApiPerfSummaryDocument? baseline)
    {
        Dictionary<string, CryptoApiPerfResult> baselineByName = baseline?.Results.ToDictionary(static result => result.Name, StringComparer.Ordinal)
            ?? new Dictionary<string, CryptoApiPerfResult>(StringComparer.Ordinal);

        StringBuilder builder = new();
        builder.AppendLine("# Crypto API performance regression baseline");
        builder.AppendLine();
        builder.AppendLine($"- Generated (UTC): {document.GeneratedUtc:O}");
        builder.AppendLine($"- Profile: {document.ProfileName}");
        builder.AppendLine($"- Warm-up: {document.WarmUpDurationSeconds:0.#} s");
        builder.AppendLine($"- Measurement window: {document.BombingDurationSeconds:0.#} s");
        builder.AppendLine($"- Single-instance concurrency: {document.SingleInstanceCopies}");
        builder.AppendLine($"- Multi-instance concurrency: {document.MultiInstanceCopies}");
        builder.AppendLine($"- SDK: {document.SdkVersion}");
        builder.AppendLine($"- Runtime: {document.RuntimeVersion}");
        builder.AppendLine($"- Host framework: {document.HostFramework}");
        builder.AppendLine($"- OS: {document.OperatingSystem}");
        builder.AppendLine($"- Architecture: {document.Architecture}");
        builder.AppendLine($"- PKCS#11 module: `{document.ModulePath}`");
        builder.AppendLine($"- Token label: `{document.TokenLabel}`");
        builder.AppendLine($"- Single-instance target: `{document.SingleBaseUrl}`");
        builder.AppendLine($"- Multi-instance target: `{document.MultiBaseUrl}`");
        builder.AppendLine();
        builder.AppendLine("## Scenario results");
        builder.AppendLine();
        builder.AppendLine("| Scenario | Topology | Workload | Req/s | Mean | P95 | P99 | Max | Ok | Fail | Baseline Δ req/s | Baseline Δ P95 |");
        builder.AppendLine("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");

        foreach (CryptoApiPerfResult result in document.Results)
        {
            baselineByName.TryGetValue(result.Name, out CryptoApiPerfResult? baselineResult);
            builder.Append("| ")
                .Append(result.Name)
                .Append(" | ")
                .Append(result.Topology)
                .Append(" | ")
                .Append(result.Workload)
                .Append(" | ")
                .Append(FormatNumber(result.RequestRate))
                .Append(" | ")
                .Append(FormatDuration(result.MeanLatencyMilliseconds))
                .Append(" | ")
                .Append(FormatDuration(result.P95LatencyMilliseconds))
                .Append(" | ")
                .Append(FormatDuration(result.P99LatencyMilliseconds))
                .Append(" | ")
                .Append(FormatDuration(result.MaxLatencyMilliseconds))
                .Append(" | ")
                .Append(result.OkCount.ToString("N0", CultureInfo.InvariantCulture))
                .Append(" | ")
                .Append(result.FailCount.ToString("N0", CultureInfo.InvariantCulture))
                .Append(" | ")
                .Append(FormatDelta(result.RequestRate, baselineResult?.RequestRate, higherIsBetter: true))
                .Append(" | ")
                .Append(FormatDelta(result.P95LatencyMilliseconds, baselineResult?.P95LatencyMilliseconds, higherIsBetter: false))
                .AppendLine(" |");
        }

        builder.AppendLine();
        builder.AppendLine("## Notes");
        builder.AppendLine();
        builder.AppendLine("- Single-instance scenarios hit one Crypto API host directly.");
        builder.AppendLine("- Multi-instance scenarios hit a local gateway fronting two Crypto API hosts with round-robin balancing.");
        builder.AppendLine("- Workload mix is deterministic and the harness is closed-loop, so the suite is good for regression detection, not vendor-certified capacity claims.");
        builder.AppendLine("- SoftHSM on one machine is a practical regression fixture, not a substitute for multi-host or real-HSM validation.");
        builder.AppendLine();
        builder.AppendLine("> Trend note: compare this file across commits or rerun artifacts to spot request-rate drops and latency-tail regressions before they escape into manual investigations.");
        return builder.ToString();
    }

    private static string FormatNumber(double value)
        => value.ToString("0.##", CultureInfo.InvariantCulture);

    private static string FormatDuration(double milliseconds)
        => string.Create(CultureInfo.InvariantCulture, $"{milliseconds:0.##} ms");

    private static string FormatDelta(double current, double? baseline, bool higherIsBetter)
    {
        if (!baseline.HasValue || baseline.Value <= 0)
        {
            return "n/a";
        }

        double percent = ((current - baseline.Value) / baseline.Value) * 100.0;
        string sign = percent > 0 ? "+" : string.Empty;
        string badge = higherIsBetter
            ? (percent >= 0 ? "better" : "worse")
            : (percent <= 0 ? "better" : "worse");

        return string.Create(CultureInfo.InvariantCulture, $"{sign}{percent:0.##}% ({badge})");
    }

    private static string ResolveRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Pkcs11Wrapper.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to resolve repository root.");
    }
}

internal sealed record CryptoApiPerfResult(
    string Name,
    string Topology,
    string Workload,
    string Description,
    string TargetBaseUrl,
    int Copies,
    int OkCount,
    int FailCount,
    double RequestRate,
    double MeanLatencyMilliseconds,
    double P50LatencyMilliseconds,
    double P95LatencyMilliseconds,
    double P99LatencyMilliseconds,
    double MaxLatencyMilliseconds);

internal sealed record CryptoApiPerfSummaryDocument(
    DateTimeOffset GeneratedUtc,
    string ProfileName,
    double WarmUpDurationSeconds,
    double BombingDurationSeconds,
    int SingleInstanceCopies,
    int MultiInstanceCopies,
    string HostFramework,
    string OperatingSystem,
    string Architecture,
    string SdkVersion,
    string RuntimeVersion,
    string ModulePath,
    string TokenLabel,
    string SingleBaseUrl,
    string MultiBaseUrl,
    IReadOnlyList<CryptoApiPerfResult> Results);
