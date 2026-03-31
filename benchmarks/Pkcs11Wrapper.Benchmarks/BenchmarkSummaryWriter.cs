using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Reports;

namespace Pkcs11Wrapper.Benchmarks;

internal static class BenchmarkSummaryWriter
{
    public static void Write(IReadOnlyList<Summary> summaries)
    {
        string repoRoot = ResolveRepoRoot();
        string resultsRoot = Environment.GetEnvironmentVariable("PKCS11_BENCHMARK_RESULTS_ROOT")
            ?? Path.Combine(repoRoot, "artifacts", "benchmarks", "latest");

        Directory.CreateDirectory(resultsRoot);

        List<BenchmarkSummaryEntry> entries = [];
        foreach (Summary summary in summaries)
        {
            foreach (BenchmarkReport report in summary.Reports)
            {
                if (report.ResultStatistics is null)
                {
                    continue;
                }

                entries.Add(new BenchmarkSummaryEntry(
                    Category: string.Join(", ", report.BenchmarkCase.Descriptor.Categories.OrderBy(static value => value, StringComparer.Ordinal)),
                    Suite: report.BenchmarkCase.Descriptor.Type.Name,
                    Benchmark: report.BenchmarkCase.Descriptor.WorkloadMethod.Name,
                    MeanNanoseconds: report.ResultStatistics.Mean,
                    StandardDeviationNanoseconds: report.ResultStatistics.StandardDeviation));
            }
        }

        entries.Sort(static (left, right) =>
        {
            int category = string.Compare(left.Category, right.Category, StringComparison.Ordinal);
            if (category != 0)
            {
                return category;
            }

            int suite = string.Compare(left.Suite, right.Suite, StringComparison.Ordinal);
            if (suite != 0)
            {
                return suite;
            }

            return left.MeanNanoseconds.CompareTo(right.MeanNanoseconds);
        });

        BenchmarkSummaryDocument document = new(
            GeneratedUtc: DateTimeOffset.UtcNow,
            HostFramework: RuntimeInformation.FrameworkDescription,
            OperatingSystem: RuntimeInformation.OSDescription,
            Architecture: RuntimeInformation.ProcessArchitecture.ToString(),
            SdkVersion: Environment.GetEnvironmentVariable("PKCS11_BENCHMARK_SDK_VERSION") ?? "unknown",
            RuntimeVersion: Environment.GetEnvironmentVariable("PKCS11_BENCHMARK_RUNTIME_VERSION") ?? "unknown",
            FixtureModulePath: Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH") ?? "unknown",
            Entries: entries);

        string markdown = BuildMarkdown(document);
        UTF8Encoding utf8 = new(encoderShouldEmitUTF8Identifier: false);
        File.WriteAllText(Path.Combine(resultsRoot, "summary.md"), markdown, utf8);
        File.WriteAllText(Path.Combine(resultsRoot, "summary.json"), JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true }), utf8);

        string? canonicalResultsPath = Environment.GetEnvironmentVariable("PKCS11_BENCHMARK_CANONICAL_RESULTS_PATH");
        if (!string.IsNullOrWhiteSpace(canonicalResultsPath))
        {
            string canonicalDirectory = Path.GetDirectoryName(canonicalResultsPath)!;
            Directory.CreateDirectory(canonicalDirectory);
            File.WriteAllText(canonicalResultsPath, markdown, utf8);
        }
    }

    private static string BuildMarkdown(BenchmarkSummaryDocument document)
    {
        StringBuilder builder = new();
        builder.AppendLine("# Performance benchmark baseline");
        builder.AppendLine();
        builder.AppendLine($"- Generated (UTC): {document.GeneratedUtc:O}");
        builder.AppendLine($"- SDK: {document.SdkVersion}");
        builder.AppendLine($"- Runtime: {document.RuntimeVersion}");
        builder.AppendLine($"- Host framework: {document.HostFramework}");
        builder.AppendLine($"- OS: {document.OperatingSystem}");
        builder.AppendLine($"- Architecture: {document.Architecture}");
        builder.AppendLine($"- PKCS#11 module: `{document.FixtureModulePath}`");
        builder.AppendLine($"- Benchmark profile: BenchmarkDotNet ShortRun + MemoryDiagnoser");
        builder.AppendLine();
        builder.AppendLine("| Category | Suite | Benchmark | Mean | StdDev | Allocated |" );
        builder.AppendLine("| --- | --- | --- | ---: | ---: | ---: |");

        foreach (BenchmarkSummaryEntry entry in document.Entries)
        {
            builder.Append("| ")
                .Append(entry.Category)
                .Append(" | ")
                .Append(entry.Suite)
                .Append(" | ")
                .Append(entry.Benchmark)
                .Append(" | ")
                .Append(FormatDuration(entry.MeanNanoseconds))
                .Append(" | ")
                .Append(FormatDuration(entry.StandardDeviationNanoseconds))
                .Append(" | ")
                .Append("n/a")
                .AppendLine(" |");
        }

        builder.AppendLine();
        builder.AppendLine("> Trend note: compare this file across commits or benchmark workflow artifacts to track whether changes improved or regressed the wrapper over time.");
        return builder.ToString();
    }

    private static string FormatDuration(double nanoseconds)
    {
        if (nanoseconds >= 1_000_000)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{nanoseconds / 1_000_000:0.###} ms");
        }

        if (nanoseconds >= 1_000)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{nanoseconds / 1_000:0.###} μs");
        }

        return string.Create(CultureInfo.InvariantCulture, $"{nanoseconds:0.###} ns");
    }

    private static string ResolveRepoRoot()
    {
        string? fromEnvironment = Environment.GetEnvironmentVariable("PKCS11_BENCHMARK_REPO_ROOT");
        if (!string.IsNullOrWhiteSpace(fromEnvironment))
        {
            return fromEnvironment;
        }

        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Pkcs11Wrapper.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to resolve the repository root for benchmark summary output.");
    }

    private sealed record BenchmarkSummaryDocument(
        DateTimeOffset GeneratedUtc,
        string HostFramework,
        string OperatingSystem,
        string Architecture,
        string SdkVersion,
        string RuntimeVersion,
        string FixtureModulePath,
        IReadOnlyList<BenchmarkSummaryEntry> Entries);

    private sealed record BenchmarkSummaryEntry(
        string Category,
        string Suite,
        string Benchmark,
        double MeanNanoseconds,
        double StandardDeviationNanoseconds);
}
