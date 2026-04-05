using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Components.Pages;

public enum SessionBulkCleanupScope
{
    AllTracked,
    Filtered,
    Invalidated
}

public sealed record SessionBulkCleanupPlan(
    SessionBulkCleanupScope Scope,
    string ScopeLabel,
    string Description,
    IReadOnlyList<AdminSessionSnapshot> Candidates,
    IReadOnlyList<AdminSessionSnapshot> IncludedSessions,
    IReadOnlyList<AdminSessionSnapshot> ExcludedSessions,
    IReadOnlyList<SessionBulkCleanupHealthGroup> HealthGroups,
    int DeviceCount,
    int HealthyCount,
    int InvalidatedCount,
    bool RequiresTypedConfirmation,
    string ConfirmationText)
{
    public int CandidateCount => Candidates.Count;
    public int IncludedCount => IncludedSessions.Count;
    public int ExcludedCount => ExcludedSessions.Count;
    public bool HasIncludedSessions => IncludedCount != 0;
    public bool HasExcludedSessions => ExcludedCount != 0;
}

public sealed record SessionBulkCleanupHealthGroup(
    string Label,
    bool IsHealthy,
    int Count,
    IReadOnlyList<SessionBulkCleanupDeviceGroup> DeviceGroups);

public sealed record SessionBulkCleanupDeviceGroup(
    Guid DeviceId,
    string DeviceName,
    int Count,
    int HealthyCount,
    int InvalidatedCount,
    IReadOnlyList<AdminSessionSnapshot> Sessions);

public sealed record SessionBulkCleanupResult(
    SessionBulkCleanupScope Scope,
    string ScopeLabel,
    int AttemptedCount,
    int ClosedCount,
    int MissingCount,
    int ExcludedCount,
    int DeviceCount,
    int HealthyCount,
    int InvalidatedCount,
    string Summary);

public static class SessionBulkCleanupView
{
    public const int TypedConfirmationThreshold = 8;

    public static SessionBulkCleanupPlan BuildPlan(
        SessionBulkCleanupScope scope,
        IReadOnlyList<AdminSessionSnapshot> sourceSessions,
        IReadOnlyCollection<Guid>? excludedSessionIds = null)
    {
        HashSet<Guid> excluded = excludedSessionIds is null ? [] : [.. excludedSessionIds];
        AdminSessionSnapshot[] orderedCandidates = OrderSessions(sourceSessions).ToArray();
        AdminSessionSnapshot[] includedSessions = orderedCandidates.Where(session => !excluded.Contains(session.SessionId)).ToArray();
        AdminSessionSnapshot[] excludedSessions = orderedCandidates.Where(session => excluded.Contains(session.SessionId)).ToArray();

        SessionBulkCleanupHealthGroup[] groups = includedSessions
            .GroupBy(session => session.IsHealthy)
            .OrderBy(group => group.Key)
            .Select(group => new SessionBulkCleanupHealthGroup(
                group.Key ? "Healthy tracked sessions" : "Invalidated tracked sessions",
                group.Key,
                group.Count(),
                group.GroupBy(session => new { session.DeviceId, session.DeviceName })
                    .Select(deviceGroup => new SessionBulkCleanupDeviceGroup(
                        deviceGroup.Key.DeviceId,
                        deviceGroup.Key.DeviceName,
                        deviceGroup.Count(),
                        deviceGroup.Count(session => session.IsHealthy),
                        deviceGroup.Count(session => !session.IsHealthy),
                        OrderSessions(deviceGroup).ToArray()))
                    .OrderBy(deviceGroup => deviceGroup.DeviceName, StringComparer.Ordinal)
                    .ToArray()))
            .ToArray();

        (string scopeLabel, string description) = GetScopeText(scope);
        int includedCount = includedSessions.Length;

        return new SessionBulkCleanupPlan(
            scope,
            scopeLabel,
            description,
            orderedCandidates,
            includedSessions,
            excludedSessions,
            groups,
            includedSessions.Select(session => session.DeviceId).Distinct().Count(),
            includedSessions.Count(session => session.IsHealthy),
            includedSessions.Count(session => !session.IsHealthy),
            includedCount >= TypedConfirmationThreshold,
            $"CLOSE {includedCount}");
    }

    public static SessionBulkCleanupResult BuildResult(SessionBulkCleanupPlan plan, int closedCount, int missingCount)
    {
        string summary = $"{plan.ScopeLabel} review finished: closed {closedCount} tracked session(s) across {plan.DeviceCount} device(s) ({plan.InvalidatedCount} invalidated, {plan.HealthyCount} healthy).";

        if (missingCount > 0)
        {
            summary += $" {missingCount} session(s) were already gone when execution started.";
        }

        if (plan.ExcludedCount > 0)
        {
            summary += $" {plan.ExcludedCount} exception(s) stayed open by operator choice.";
        }

        if (closedCount == 0 && plan.IncludedCount > 0)
        {
            summary = $"{plan.ScopeLabel} review finished: no tracked sessions were closed.";
            if (missingCount > 0)
            {
                summary += $" {missingCount} session(s) were already gone when execution started.";
            }

            if (plan.ExcludedCount > 0)
            {
                summary += $" {plan.ExcludedCount} exception(s) stayed open by operator choice.";
            }
        }

        if (plan.IncludedCount == 0)
        {
            summary = $"{plan.ScopeLabel} review finished with no included tracked sessions. Restore an exception or start a new review to close anything.";
        }

        return new SessionBulkCleanupResult(
            plan.Scope,
            plan.ScopeLabel,
            plan.IncludedCount,
            closedCount,
            missingCount,
            plan.ExcludedCount,
            plan.DeviceCount,
            plan.HealthyCount,
            plan.InvalidatedCount,
            summary);
    }

    private static IEnumerable<AdminSessionSnapshot> OrderSessions(IEnumerable<AdminSessionSnapshot> sessions)
        => sessions
            .OrderBy(session => session.IsHealthy)
            .ThenBy(session => session.DeviceName, StringComparer.Ordinal)
            .ThenBy(session => session.SlotId)
            .ThenByDescending(session => session.LastTouchedUtc)
            .ThenBy(session => session.SessionId);

    private static (string ScopeLabel, string Description) GetScopeText(SessionBulkCleanupScope scope)
        => scope switch
        {
            SessionBulkCleanupScope.Filtered => (
                "Close Filtered",
                "Review only the tracked sessions currently visible under the active search and filter state before any close requests are sent."),
            SessionBulkCleanupScope.Invalidated => (
                "Close Invalidated",
                "Review already-broken tracked sessions, remove the rare exceptions you want to keep open for inspection, then close the remainder deliberately."),
            _ => (
                "Close All Tracked",
                "Review every tracked session first so large cleanup passes stay visible, grouped, and reversible until you explicitly execute them.")
        };
}
