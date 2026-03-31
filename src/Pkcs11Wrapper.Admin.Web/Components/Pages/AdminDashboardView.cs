using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Lab;

namespace Pkcs11Wrapper.Admin.Web.Components.Pages;

public sealed record DashboardFailureCategoryItem(
    string Category,
    int Count,
    DateTimeOffset LatestTimestampUtc,
    string LatestAction,
    string LatestTarget);

public sealed record DashboardInvalidatedDeviceItem(
    Guid DeviceId,
    string DeviceName,
    int Count,
    DateTimeOffset LatestTouchedUtc,
    string LatestReason);

public static class AdminDashboardView
{
    public static IReadOnlyList<DashboardFailureCategoryItem> BuildFailureCategories(IReadOnlyList<AdminAuditLogEntry> logs, int take = 5)
        => logs
            .Where(log => !string.Equals(log.Outcome, "Success", StringComparison.OrdinalIgnoreCase))
            .GroupBy(log => log.Category, StringComparer.Ordinal)
            .Select(group =>
            {
                AdminAuditLogEntry latest = group.OrderByDescending(log => log.TimestampUtc).First();
                return new DashboardFailureCategoryItem(group.Key, group.Count(), latest.TimestampUtc, latest.Action, latest.Target);
            })
            .OrderByDescending(item => item.Count)
            .ThenByDescending(item => item.LatestTimestampUtc)
            .Take(Math.Max(take, 1))
            .ToArray();

    public static IReadOnlyList<DashboardInvalidatedDeviceItem> BuildInvalidatedDevices(IReadOnlyList<AdminSessionSnapshot> sessions)
        => sessions
            .Where(session => !session.IsHealthy)
            .GroupBy(session => new { session.DeviceId, session.DeviceName })
            .Select(group =>
            {
                AdminSessionSnapshot latest = group.OrderByDescending(session => session.LastTouchedUtc).First();
                return new DashboardInvalidatedDeviceItem(
                    group.Key.DeviceId,
                    group.Key.DeviceName,
                    group.Count(),
                    latest.LastTouchedUtc,
                    latest.InvalidationReason ?? latest.LastOperation);
            })
            .OrderByDescending(item => item.Count)
            .ThenByDescending(item => item.LatestTouchedUtc)
            .ToArray();

    public static DateTimeOffset? GetLastSuccessfulConfigurationExportUtc(IReadOnlyList<AdminAuditLogEntry> logs)
        => logs
            .Where(log => string.Equals(log.Category, "Configuration", StringComparison.Ordinal)
                && string.Equals(log.Action, "Export", StringComparison.Ordinal)
                && string.Equals(log.Outcome, "Success", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(log => log.TimestampUtc)
            .Select(log => (DateTimeOffset?)log.TimestampUtc)
            .FirstOrDefault();

    public static IReadOnlyList<string> GetRecentTemplateNames(IReadOnlyList<Pkcs11LabSavedTemplate> templates, int take = 5)
        => templates
            .OrderByDescending(template => template.UpdatedUtc)
            .ThenBy(template => template.Name, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(take, 1))
            .Select(template => template.Name)
            .ToArray();
}
