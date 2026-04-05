using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Components.Pages;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class SessionBulkCleanupViewTests
{
    [Fact]
    public void BuildPlanGroupsInvalidatedSessionsBeforeHealthySessions()
    {
        Guid primaryDevice = Guid.NewGuid();
        Guid backupDevice = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminSessionSnapshot[] sessions =
        [
            CreateSession(primaryDevice, "Primary", true, now.AddMinutes(-1), slotId: 1, operation: "GetSessionInfo", reason: null),
            CreateSession(primaryDevice, "Primary", false, now.AddMinutes(-2), slotId: 1, operation: "CloseAllSessions", reason: "Invalidated by slot close-all."),
            CreateSession(backupDevice, "Backup", false, now.AddMinutes(-3), slotId: 2, operation: "CloseSession", reason: "Handle no longer responds.")
        ];

        SessionBulkCleanupPlan plan = SessionBulkCleanupView.BuildPlan(SessionBulkCleanupScope.AllTracked, sessions);

        Assert.Equal("Close All Tracked", plan.ScopeLabel);
        Assert.Equal(3, plan.IncludedCount);
        Assert.Equal(2, plan.InvalidatedCount);
        Assert.Equal(1, plan.HealthyCount);
        Assert.Equal(2, plan.HealthGroups.Count);
        Assert.False(plan.HealthGroups[0].IsHealthy);
        Assert.Equal("Invalidated tracked sessions", plan.HealthGroups[0].Label);
        Assert.Equal(2, plan.HealthGroups[0].Count);
        Assert.True(plan.HealthGroups[1].IsHealthy);
        Assert.Equal("Healthy tracked sessions", plan.HealthGroups[1].Label);
        Assert.Equal(2, plan.DeviceCount);
    }

    [Fact]
    public void BuildPlanRemovesExcludedSessionsAndRequiresTypedConfirmationForLargeBatches()
    {
        Guid deviceId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminSessionSnapshot[] sessions = Enumerable.Range(0, SessionBulkCleanupView.TypedConfirmationThreshold)
            .Select(index => CreateSession(deviceId, "Primary", index % 2 == 0, now.AddMinutes(-index), slotId: (nuint)(index + 1), operation: "GetSessionInfo", reason: index % 2 == 0 ? null : "Invalidated by review."))
            .ToArray();

        Guid excludedSessionId = sessions[0].SessionId;
        SessionBulkCleanupPlan plan = SessionBulkCleanupView.BuildPlan(SessionBulkCleanupScope.Filtered, sessions, [excludedSessionId]);

        Assert.Equal("Close Filtered", plan.ScopeLabel);
        Assert.Equal(SessionBulkCleanupView.TypedConfirmationThreshold - 1, plan.IncludedCount);
        Assert.Single(plan.ExcludedSessions);
        Assert.Equal(excludedSessionId, plan.ExcludedSessions[0].SessionId);
        Assert.False(plan.RequiresTypedConfirmation);
        Assert.Equal($"CLOSE {plan.IncludedCount}", plan.ConfirmationText);
    }

    [Fact]
    public void BuildResultSummarizesClosedMissingAndExcludedCounts()
    {
        Guid deviceId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminSessionSnapshot[] sessions =
        [
            CreateSession(deviceId, "Primary", false, now.AddMinutes(-2), slotId: 1, operation: "CloseAllSessions", reason: "Invalidated by slot close-all."),
            CreateSession(deviceId, "Primary", true, now.AddMinutes(-1), slotId: 1, operation: "GetSessionInfo", reason: null),
            CreateSession(deviceId, "Primary", false, now.AddMinutes(-3), slotId: 1, operation: "CloseSession", reason: "Handle missing.")
        ];

        SessionBulkCleanupPlan plan = SessionBulkCleanupView.BuildPlan(SessionBulkCleanupScope.Invalidated, sessions, [sessions[1].SessionId]);
        SessionBulkCleanupResult result = SessionBulkCleanupView.BuildResult(plan, closedCount: 1, missingCount: 1);

        Assert.Equal("Close Invalidated", result.ScopeLabel);
        Assert.Equal(2, result.AttemptedCount);
        Assert.Equal(1, result.ClosedCount);
        Assert.Equal(1, result.MissingCount);
        Assert.Equal(1, result.ExcludedCount);
        Assert.Contains("closed 1 tracked session(s)", result.Summary, StringComparison.Ordinal);
        Assert.Contains("1 session(s) were already gone", result.Summary, StringComparison.Ordinal);
        Assert.Contains("1 exception(s) stayed open", result.Summary, StringComparison.Ordinal);
    }

    private static AdminSessionSnapshot CreateSession(
        Guid deviceId,
        string deviceName,
        bool healthy,
        DateTimeOffset touchedUtc,
        nuint slotId,
        string operation,
        string? reason)
        => new(
            Guid.NewGuid(),
            deviceId,
            deviceName,
            slotId,
            true,
            "R/W User Functions",
            "RW_SESSION,SERIAL_SESSION",
            0,
            healthy,
            false,
            touchedUtc.AddMinutes(-5),
            touchedUtc,
            operation,
            healthy,
            healthy ? "healthy session" : "needs review",
            healthy ? "Healthy" : "Invalidated",
            reason,
            healthy,
            healthy,
            healthy,
            true,
            true);
}
