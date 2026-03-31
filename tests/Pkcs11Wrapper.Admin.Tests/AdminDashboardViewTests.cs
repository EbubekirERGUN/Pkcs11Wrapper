using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Components.Pages;
using Pkcs11Wrapper.Admin.Web.Lab;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class AdminDashboardViewTests
{
    [Fact]
    public void BuildFailureCategoriesGroupsAndOrdersFailures()
    {
        AdminAuditLogEntry[] logs =
        [
            CreateAudit("Lab", "SignData", "slot-1", "Failure", DateTimeOffset.UtcNow.AddMinutes(-3)),
            CreateAudit("Lab", "VerifySignature", "slot-1", "Failure", DateTimeOffset.UtcNow.AddMinutes(-2)),
            CreateAudit("Configuration", "Import", "bundle.json", "Failure", DateTimeOffset.UtcNow.AddMinutes(-1)),
            CreateAudit("Configuration", "Export", "bundle.json", "Success", DateTimeOffset.UtcNow)
        ];

        IReadOnlyList<DashboardFailureCategoryItem> items = AdminDashboardView.BuildFailureCategories(logs);

        Assert.Equal(2, items.Count);
        Assert.Equal("Lab", items[0].Category);
        Assert.Equal(2, items[0].Count);
        Assert.Equal("VerifySignature", items[0].LatestAction);
    }

    [Fact]
    public void BuildInvalidatedDevicesAggregatesPerDevice()
    {
        Guid deviceA = Guid.NewGuid();
        Guid deviceB = Guid.NewGuid();
        AdminSessionSnapshot[] sessions =
        [
            CreateSession(deviceA, "Primary", false, DateTimeOffset.UtcNow.AddMinutes(-5), "handle invalidated"),
            CreateSession(deviceA, "Primary", false, DateTimeOffset.UtcNow.AddMinutes(-1), "close-all invoked"),
            CreateSession(deviceB, "Backup", true, DateTimeOffset.UtcNow.AddMinutes(-2), null)
        ];

        IReadOnlyList<DashboardInvalidatedDeviceItem> items = AdminDashboardView.BuildInvalidatedDevices(sessions);

        Assert.Single(items);
        Assert.Equal(deviceA, items[0].DeviceId);
        Assert.Equal(2, items[0].Count);
        Assert.Equal("close-all invoked", items[0].LatestReason);
    }

    [Fact]
    public void GetLastSuccessfulConfigurationExportUtcReturnsLatestMatch()
    {
        DateTimeOffset expected = DateTimeOffset.UtcNow.AddMinutes(-1);
        AdminAuditLogEntry[] logs =
        [
            CreateAudit("Configuration", "Export", "older.json", "Success", DateTimeOffset.UtcNow.AddMinutes(-5)),
            CreateAudit("Configuration", "Import", "bundle.json", "Success", DateTimeOffset.UtcNow.AddMinutes(-2)),
            CreateAudit("Configuration", "Export", "latest.json", "Success", expected)
        ];

        Assert.Equal(expected, AdminDashboardView.GetLastSuccessfulConfigurationExportUtc(logs));
    }

    [Fact]
    public void GetRecentTemplateNamesReturnsLatestNames()
    {
        Pkcs11LabSavedTemplate[] templates =
        [
            new(Guid.NewGuid(), "older", null, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(-5), new Pkcs11LabRequest()),
            new(Guid.NewGuid(), "latest", null, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(-1), new Pkcs11LabRequest()),
            new(Guid.NewGuid(), "middle", null, DateTimeOffset.UtcNow.AddMinutes(-3), DateTimeOffset.UtcNow.AddMinutes(-3), new Pkcs11LabRequest())
        ];

        IReadOnlyList<string> names = AdminDashboardView.GetRecentTemplateNames(templates, take: 2);

        Assert.Equal(new[] { "latest", "middle" }, names);
    }

    private static AdminAuditLogEntry CreateAudit(string category, string action, string target, string outcome, DateTimeOffset timestampUtc)
        => new(
            Guid.NewGuid(),
            timestampUtc,
            "tester",
            [AdminRoles.Admin],
            "cookie",
            category,
            action,
            target,
            outcome,
            $"{action} -> {target}",
            1,
            null,
            "hash",
            "127.0.0.1",
            "session-1",
            "tests",
            Environment.MachineName);

    private static AdminSessionSnapshot CreateSession(Guid deviceId, string deviceName, bool healthy, DateTimeOffset touchedUtc, string? reason)
        => new(
            Guid.NewGuid(),
            deviceId,
            deviceName,
            1,
            true,
            "R/W User Functions",
            "RW_SESSION,SERIAL_SESSION",
            0,
            true,
            false,
            touchedUtc.AddMinutes(-2),
            touchedUtc,
            healthy ? "GetSessionInfo" : "CloseAllSessions",
            healthy,
            null,
            healthy ? "Healthy" : "Invalidated",
            reason,
            healthy,
            healthy,
            healthy,
            true,
            true);
}
