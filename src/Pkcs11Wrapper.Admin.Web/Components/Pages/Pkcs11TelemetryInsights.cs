using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Components.Pages;

public sealed record Pkcs11TelemetryInsights(
    int TotalCount,
    int NonSuccessCount,
    int SlowCount,
    double FailureRate,
    double SlowRate,
    double P95DurationMilliseconds,
    double MaxDurationMilliseconds,
    string? HottestOperationName,
    int HottestOperationCount,
    Pkcs11TelemetryTrendBucket[] Trend,
    Pkcs11TelemetryOperationSummary[] TopOperations,
    Pkcs11TelemetryFailureHotspot[] FailureHotspots)
{
    public static Pkcs11TelemetryInsights Empty { get; } = new(
        TotalCount: 0,
        NonSuccessCount: 0,
        SlowCount: 0,
        FailureRate: 0,
        SlowRate: 0,
        P95DurationMilliseconds: 0,
        MaxDurationMilliseconds: 0,
        HottestOperationName: null,
        HottestOperationCount: 0,
        Trend: [],
        TopOperations: [],
        FailureHotspots: []);

    public static Pkcs11TelemetryInsights Build(
        IReadOnlyList<AdminPkcs11TelemetryEntry> items,
        DateTimeOffset nowUtc,
        double slowOperationThresholdMilliseconds,
        int trendBucketCount = 6,
        int maxTopOperations = 5,
        int maxFailureHotspots = 5)
    {
        if (items.Count == 0)
        {
            return Empty;
        }

        int nonSuccessCount = items.Count(static item => !IsSuccess(item));
        int slowCount = slowOperationThresholdMilliseconds > 0
            ? items.Count(item => item.DurationMilliseconds >= slowOperationThresholdMilliseconds)
            : 0;
        double[] orderedDurations = [.. items.Select(item => item.DurationMilliseconds).OrderBy(static value => value)];

        Pkcs11TelemetryOperationSummary[] topOperations =
        [
            .. items
                .GroupBy(item => item.OperationName, StringComparer.Ordinal)
                .Select(group => new Pkcs11TelemetryOperationSummary(
                    group.Key,
                    group.Count(),
                    group.Count(static item => !IsSuccess(item)),
                    group.Average(static item => item.DurationMilliseconds),
                    group.Max(static item => item.DurationMilliseconds),
                    group.Select(static item => item.DeviceName)
                        .Distinct(StringComparer.Ordinal)
                        .OrderBy(static name => name, StringComparer.Ordinal)
                        .ToArray()))
                .OrderByDescending(static summary => summary.TotalCount)
                .ThenByDescending(static summary => summary.NonSuccessCount)
                .ThenByDescending(static summary => summary.MaxDurationMilliseconds)
                .ThenBy(static summary => summary.OperationName, StringComparer.Ordinal)
                .Take(Math.Max(1, maxTopOperations))
        ];

        Pkcs11TelemetryFailureHotspot[] failureHotspots =
        [
            .. items
                .Where(static item => !IsSuccess(item))
                .GroupBy(static item => new FailureHotspotKey(item.OperationName, item.DeviceName, GetFailureSignature(item)))
                .Select(group => new Pkcs11TelemetryFailureHotspot(
                    group.Key.OperationName,
                    group.Key.DeviceName,
                    group.Key.FailureSignature,
                    group.Count(),
                    group.Max(static item => item.TimestampUtc),
                    group.Max(static item => item.DurationMilliseconds)))
                .OrderByDescending(static hotspot => hotspot.Count)
                .ThenByDescending(static hotspot => hotspot.LatestTimestampUtc)
                .ThenByDescending(static hotspot => hotspot.MaxDurationMilliseconds)
                .ThenBy(static hotspot => hotspot.OperationName, StringComparer.Ordinal)
                .ThenBy(static hotspot => hotspot.DeviceName, StringComparer.Ordinal)
                .Take(Math.Max(1, maxFailureHotspots))
        ];

        Pkcs11TelemetryOperationSummary? hottestOperation = topOperations.FirstOrDefault();
        return new(
            TotalCount: items.Count,
            NonSuccessCount: nonSuccessCount,
            SlowCount: slowCount,
            FailureRate: items.Count == 0 ? 0 : nonSuccessCount / (double)items.Count,
            SlowRate: items.Count == 0 ? 0 : slowCount / (double)items.Count,
            P95DurationMilliseconds: CalculatePercentile(orderedDurations, 0.95),
            MaxDurationMilliseconds: orderedDurations[^1],
            HottestOperationName: hottestOperation?.OperationName,
            HottestOperationCount: hottestOperation?.TotalCount ?? 0,
            Trend: BuildTrend(items, nowUtc, trendBucketCount),
            TopOperations: topOperations,
            FailureHotspots: failureHotspots);
    }

    private static Pkcs11TelemetryTrendBucket[] BuildTrend(
        IReadOnlyList<AdminPkcs11TelemetryEntry> items,
        DateTimeOffset nowUtc,
        int requestedBucketCount)
    {
        int bucketCount = Math.Max(3, requestedBucketCount);
        DateTimeOffset newest = items.Max(static item => item.TimestampUtc);
        DateTimeOffset oldest = items.Min(static item => item.TimestampUtc);
        DateTimeOffset end = newest;
        DateTimeOffset start = oldest;

        if (end - start < TimeSpan.FromMinutes(1))
        {
            start = end.AddMinutes(-1);
        }

        TimeSpan span = end - start;
        long bucketTicks = Math.Max(1, span.Ticks / bucketCount);
        int[] totals = new int[bucketCount];
        int[] nonSuccessCounts = new int[bucketCount];

        foreach (AdminPkcs11TelemetryEntry item in items)
        {
            long offsetTicks = Math.Max(0, item.TimestampUtc.Ticks - start.Ticks);
            int index = (int)Math.Min(bucketCount - 1, offsetTicks / bucketTicks);
            totals[index]++;
            if (!IsSuccess(item))
            {
                nonSuccessCounts[index]++;
            }
        }

        Pkcs11TelemetryTrendBucket[] buckets = new Pkcs11TelemetryTrendBucket[bucketCount];
        for (int i = 0; i < bucketCount; i++)
        {
            DateTimeOffset bucketEnd = i == bucketCount - 1
                ? end
                : start.AddTicks(bucketTicks * (i + 1));
            buckets[i] = new(
                Label: FormatTrendLabel(bucketEnd, span),
                TotalCount: totals[i],
                NonSuccessCount: nonSuccessCounts[i]);
        }

        return buckets;
    }

    private static string FormatTrendLabel(DateTimeOffset bucketEnd, TimeSpan span)
        => span <= TimeSpan.FromHours(24)
            ? bucketEnd.ToLocalTime().ToString("HH:mm")
            : span <= TimeSpan.FromDays(7)
                ? bucketEnd.ToLocalTime().ToString("MM-dd HH:mm")
                : bucketEnd.ToLocalTime().ToString("yyyy-MM-dd");

    private static double CalculatePercentile(IReadOnlyList<double> orderedValues, double percentile)
    {
        if (orderedValues.Count == 0)
        {
            return 0;
        }

        if (orderedValues.Count == 1)
        {
            return orderedValues[0];
        }

        double position = (orderedValues.Count - 1) * percentile;
        int lowerIndex = (int)Math.Floor(position);
        int upperIndex = (int)Math.Ceiling(position);
        if (lowerIndex == upperIndex)
        {
            return orderedValues[lowerIndex];
        }

        double lower = orderedValues[lowerIndex];
        double upper = orderedValues[upperIndex];
        double weight = position - lowerIndex;
        return lower + ((upper - lower) * weight);
    }

    private static bool IsSuccess(AdminPkcs11TelemetryEntry item)
        => string.Equals(item.Status, "Succeeded", StringComparison.Ordinal);

    private static string GetFailureSignature(AdminPkcs11TelemetryEntry item)
        => !string.IsNullOrWhiteSpace(item.ReturnValue)
            ? item.ReturnValue
            : !string.IsNullOrWhiteSpace(item.ExceptionType)
                ? item.ExceptionType
                : item.Status;

    private sealed record FailureHotspotKey(string OperationName, string DeviceName, string FailureSignature);
}

public sealed record Pkcs11TelemetryTrendBucket(
    string Label,
    int TotalCount,
    int NonSuccessCount);

public sealed record Pkcs11TelemetryOperationSummary(
    string OperationName,
    int TotalCount,
    int NonSuccessCount,
    double AverageDurationMilliseconds,
    double MaxDurationMilliseconds,
    IReadOnlyList<string> Devices);

public sealed record Pkcs11TelemetryFailureHotspot(
    string OperationName,
    string DeviceName,
    string FailureSignature,
    int Count,
    DateTimeOffset LatestTimestampUtc,
    double MaxDurationMilliseconds);