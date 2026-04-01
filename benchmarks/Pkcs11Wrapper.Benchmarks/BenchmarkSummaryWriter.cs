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

                long? allocatedBytesPerOperation = report.GcStats.GetBytesAllocatedPerOperation(report.BenchmarkCase);
                long? totalAllocatedBytes = report.GcStats.GetTotalAllocatedBytes(excludeAllocationQuantumSideEffects: true);

                entries.Add(new BenchmarkSummaryEntry(
                    Category: string.Join(", ", report.BenchmarkCase.Descriptor.Categories.OrderBy(static value => value, StringComparer.Ordinal)),
                    Suite: report.BenchmarkCase.Descriptor.Type.Name,
                    Benchmark: report.BenchmarkCase.Descriptor.WorkloadMethod.Name,
                    MeanNanoseconds: report.ResultStatistics.Mean,
                    StandardDeviationNanoseconds: report.ResultStatistics.StandardDeviation,
                    AllocatedBytesPerOperation: allocatedBytesPerOperation,
                    TotalAllocatedBytes: totalAllocatedBytes,
                    Gen0Collections: report.GcStats.Gen0Collections,
                    Gen1Collections: report.GcStats.Gen1Collections,
                    Gen2Collections: report.GcStats.Gen2Collections));
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
        string json = JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
        UTF8Encoding utf8 = new(encoderShouldEmitUTF8Identifier: false);

        File.WriteAllText(Path.Combine(resultsRoot, "summary.md"), markdown, utf8);
        File.WriteAllText(Path.Combine(resultsRoot, "summary.json"), json, utf8);

        string? canonicalMarkdownPath = Environment.GetEnvironmentVariable("PKCS11_BENCHMARK_CANONICAL_RESULTS_PATH");
        if (!string.IsNullOrWhiteSpace(canonicalMarkdownPath))
        {
            WriteCanonicalFile(canonicalMarkdownPath, markdown, utf8);
        }

        string? canonicalJsonPath = Environment.GetEnvironmentVariable("PKCS11_BENCHMARK_CANONICAL_JSON_PATH");
        if (!string.IsNullOrWhiteSpace(canonicalJsonPath))
        {
            WriteCanonicalFile(canonicalJsonPath, json, utf8);
        }
    }

    private static void WriteCanonicalFile(string path, string content, Encoding encoding)
    {
        string canonicalDirectory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(canonicalDirectory);
        File.WriteAllText(path, content, encoding);
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
        builder.AppendLine("- Benchmark profile: BenchmarkDotNet ShortRun + MemoryDiagnoser");
        builder.AppendLine();
        builder.AppendLine("| Category | Suite | Benchmark | Mean | StdDev | Allocated | Gen0 | Gen1 | Gen2 |");
        builder.AppendLine("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |");

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
                .Append(FormatAllocatedBytes(entry.AllocatedBytesPerOperation))
                .Append(" | ")
                .Append(entry.Gen0Collections)
                .Append(" | ")
                .Append(entry.Gen1Collections)
                .Append(" | ")
                .Append(entry.Gen2Collections)
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

    private static string FormatAllocatedBytes(long? bytes)
    {
        if (!bytes.HasValue)
        {
            return "n/a";
        }

        if (bytes.Value == 0)
        {
            return "0 B";
        }

        return string.Create(CultureInfo.InvariantCulture, $"{bytes.Value:N0} B");
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
        double StandardDeviationNanoseconds,
        long? AllocatedBytesPerOperation,
        long? TotalAllocatedBytes,
        int Gen0Collections,
        int Gen1Collections,
        int Gen2Collections);
}
