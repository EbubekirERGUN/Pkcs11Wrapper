using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class DashboardSummaryTests
{
    [Fact]
    public async Task GetDashboardAsyncAggregatesDeviceAndAuditHealth()
    {
        HsmAdminService service = CreateService(
        [
            CreateProfile(Guid.NewGuid(), "Primary", "/usr/lib/libpkcs11-primary.so", isEnabled: true),
            CreateProfile(Guid.NewGuid(), "Backup", "/usr/lib/libpkcs11-backup.so", isEnabled: true),
            CreateProfile(Guid.NewGuid(), "Disabled", "/usr/lib/libpkcs11-disabled.so", isEnabled: false)
        ],
        [
            CreateAuditEntry("Device", "Save", "Primary", "Success"),
            CreateAuditEntry("Lab", "SignData", "Primary/slot-0", "Failure"),
            CreateAuditEntry("AdminUsers", "RotatePassword", "operator1", "Success")
        ],
        new AuditIntegrityStatus(false, 3, "2", "Audit chain mismatch detected.", "Entry 2 previous-hash mismatch."));

        DashboardSummary summary = await service.GetDashboardAsync();

        Assert.Equal(3, summary.DeviceCount);
        Assert.Equal(2, summary.EnabledDeviceCount);
        Assert.Equal(1, summary.DisabledDeviceCount);
        Assert.Equal(0, summary.ActiveSessionCount);
        Assert.Equal(0, summary.HealthySessionCount);
        Assert.Equal(0, summary.InvalidatedSessionCount);
        Assert.Equal(3, summary.RecentAuditCount);
        Assert.Equal(1, summary.RecentAuditFailureCount);
        Assert.False(summary.AuditIntegrityValid);
        Assert.Equal("Audit chain mismatch detected.", summary.AuditIntegritySummary);
    }

    private static HsmAdminService CreateService(IReadOnlyList<HsmDeviceProfile> devices, IReadOnlyList<AdminAuditLogEntry> auditEntries, AuditIntegrityStatus integrity)
    {
        DeviceProfileService deviceProfiles = new(new InMemoryDeviceProfileStore(devices));
        AuditLogService auditLog = new(new InMemoryAuditLogStore(auditEntries, integrity), new TestActorContext());
        return new HsmAdminService(deviceProfiles, auditLog, new AdminSessionRegistry(), new AllowAllAuthorizationService(), new AdminPkcs11Runtime());
    }

    private static HsmDeviceProfile CreateProfile(Guid id, string name, string modulePath, bool isEnabled)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new HsmDeviceProfile(id, name, modulePath, null, null, isEnabled, now, now);
    }

    private static AdminAuditLogEntry CreateAuditEntry(string category, string action, string target, string outcome)
        => new(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
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

    private sealed class InMemoryDeviceProfileStore(IReadOnlyList<HsmDeviceProfile> seed) : IDeviceProfileStore
    {
        private List<HsmDeviceProfile> _devices = [.. seed];

        public Task<IReadOnlyList<HsmDeviceProfile>> GetAllAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<HsmDeviceProfile>>([.. _devices]);

        public Task SaveAllAsync(IReadOnlyList<HsmDeviceProfile> devices, CancellationToken cancellationToken = default)
        {
            _devices = [.. devices];
            return Task.CompletedTask;
        }
    }

    private sealed class InMemoryAuditLogStore(IReadOnlyList<AdminAuditLogEntry> seed, AuditIntegrityStatus integrity) : IAuditLogStore
    {
        private readonly List<AdminAuditLogEntry> _entries = [.. seed];

        public Task AppendAsync(AdminAuditLogEntry entry, CancellationToken cancellationToken = default)
        {
            _entries.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AdminAuditLogEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AdminAuditLogEntry>>(_entries.TakeLast(take).Reverse().ToArray());

        public Task<AuditIntegrityStatus> VerifyIntegrityAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(integrity);
    }

    private sealed class TestActorContext : IAdminActorContext
    {
        public AdminActorInfo GetCurrent()
            => new("tester", "cookie", true, [AdminRoles.Admin], "127.0.0.1", "session-1", "tests");
    }

    private sealed class AllowAllAuthorizationService : IAdminAuthorizationService
    {
        public void DemandAdmin()
        {
        }

        public void DemandOperator()
        {
        }

        public void DemandViewer()
        {
        }
    }
}
