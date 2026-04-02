using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Components.Pages;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class Pkcs11TelemetryInsightsTests
{
    [Fact]
    public void BuildSummarizesFailureRateSlowOpsAndTopOperations()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminPkcs11TelemetryEntry[] items =
        [
            CreateEntry("Primary", "SignData", "Succeeded", now.AddMinutes(-12), durationMilliseconds: 22),
            CreateEntry("Primary", "SignData", "Failed", now.AddMinutes(-10), returnValue: "CKR_PIN_INCORRECT", durationMilliseconds: 520),
            CreateEntry("Primary", "SignData", "Failed", now.AddMinutes(-8), returnValue: "CKR_PIN_INCORRECT", durationMilliseconds: 410),
            CreateEntry("Backup", "FindObjects", "Succeeded", now.AddMinutes(-6), durationMilliseconds: 90),
            CreateEntry("Backup", "FindObjects", "Succeeded", now.AddMinutes(-4), durationMilliseconds: 95),
            CreateEntry("Primary", "OpenSession", "Succeeded", now.AddMinutes(-2), durationMilliseconds: 12)
        ];

        Pkcs11TelemetryInsights insights = Pkcs11TelemetryInsights.Build(items, now, slowOperationThresholdMilliseconds: 250);

        Assert.Equal(6, insights.TotalCount);
        Assert.Equal(2, insights.NonSuccessCount);
        Assert.Equal(2, insights.SlowCount);
        Assert.Equal("SignData", insights.HottestOperationName);
        Assert.Equal(3, insights.HottestOperationCount);
        Assert.True(insights.FailureRate > 0.3 && insights.FailureRate < 0.4);
        Assert.True(insights.P95DurationMilliseconds >= 490);

        Pkcs11TelemetryOperationSummary topOperation = insights.TopOperations[0];
        Assert.Equal("SignData", topOperation.OperationName);
        Assert.Equal(3, topOperation.TotalCount);
        Assert.Equal(2, topOperation.NonSuccessCount);
        Assert.Contains("Primary", topOperation.Devices);

        Pkcs11TelemetryFailureHotspot hotspot = Assert.Single(insights.FailureHotspots);
        Assert.Equal("SignData", hotspot.OperationName);
        Assert.Equal("Primary", hotspot.DeviceName);
        Assert.Equal("CKR_PIN_INCORRECT", hotspot.FailureSignature);
        Assert.Equal(2, hotspot.Count);
    }

    [Fact]
    public void BuildCreatesTrendBucketsThatAccountForEveryEvent()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminPkcs11TelemetryEntry[] items =
        [
            CreateEntry("Primary", "OpenSession", "Succeeded", now.AddMinutes(-50), durationMilliseconds: 5),
            CreateEntry("Primary", "Login", "Failed", now.AddMinutes(-40), returnValue: "CKR_PIN_INCORRECT", durationMilliseconds: 35),
            CreateEntry("Primary", "FindObjects", "Succeeded", now.AddMinutes(-30), durationMilliseconds: 60),
            CreateEntry("Primary", "SignData", "Succeeded", now.AddMinutes(-20), durationMilliseconds: 85),
            CreateEntry("Primary", "Verify", "ReturnedFalse", now.AddMinutes(-10), returnValue: "CKR_SIGNATURE_INVALID", durationMilliseconds: 110),
            CreateEntry("Primary", "Logout", "Succeeded", now.AddMinutes(-2), durationMilliseconds: 8)
        ];

        Pkcs11TelemetryInsights insights = Pkcs11TelemetryInsights.Build(items, now, slowOperationThresholdMilliseconds: 250, trendBucketCount: 6);

        Assert.Equal(6, insights.Trend.Length);
        Assert.Equal(items.Length, insights.Trend.Sum(bucket => bucket.TotalCount));
        Assert.Equal(2, insights.Trend.Sum(bucket => bucket.NonSuccessCount));
        Assert.Contains(insights.Trend, bucket => bucket.TotalCount > 0 && !string.IsNullOrWhiteSpace(bucket.Label));
    }

    private static AdminPkcs11TelemetryEntry CreateEntry(
        string deviceName,
        string operationName,
        string status,
        DateTimeOffset timestampUtc,
        string? returnValue = null,
        double durationMilliseconds = 4.2)
        => new(
            Guid.NewGuid(),
            timestampUtc,
            Guid.NewGuid(),
            deviceName,
            operationName,
            $"C_{operationName}",
            status,
            durationMilliseconds,
            returnValue,
            1,
            99,
            operationName.StartsWith("Sign", StringComparison.Ordinal) ? 0x40UL : null,
            status == "Failed" ? "Pkcs11Exception" : null,
            "alice",
            "cookie",
            "trace-1",
            "corr-1",
            []);
}
