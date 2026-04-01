using System.Text.Json;
using Pkcs11Wrapper.Admin.Application;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class HsmAdminServiceReconciliationTests
{
    [Fact]
    public async Task SaveDeviceAsyncConfigChangeInvalidatesTrackedSessionsAndCleansDependentState()
    {
        Guid deviceId = Guid.NewGuid();
        HsmDeviceProfile existing = CreateProfile(deviceId, "Primary", "/tmp/original.so", isEnabled: true);
        InMemoryDeviceProfileStore store = new([existing]);
        DeviceProfileService deviceProfiles = new(store);
        InMemoryAuditLogStore auditStore = new();
        AdminSessionRegistry registry = new(new AdminSessionRegistryOptions { IdleTimeout = TimeSpan.FromHours(1) });
        AdminSessionSnapshot tracked = registry.RegisterSyntheticForTesting(deviceId, existing.Name, 1, isReadWrite: true, notes: "tracked");
        FakeDependencyCleanupService cleanup = new();
        HsmAdminService service = new(deviceProfiles, new AuditLogService(auditStore, new TestActorContext()), registry, new AllowAllAuthorizationService(), cleanup);

        await service.SaveDeviceAsync(deviceId, new HsmDeviceProfileInput
        {
            Name = existing.Name,
            ModulePath = "/tmp/updated.so",
            IsEnabled = false
        });

        AdminSessionSnapshot snapshot = service.GetSessions().Single(session => session.SessionId == tracked.SessionId);
        Assert.False(snapshot.IsHealthy);
        Assert.Equal("Invalidated", snapshot.HealthLabel);
        Assert.Equal([deviceId], cleanup.CleanedDeviceIds);
        Assert.Contains(auditStore.Entries, entry => entry.Category == "Device" && entry.Action == "Update" && entry.Details.Contains("Reconciled dependencies", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ImportConfigurationAsyncReplaceAllCleansMissingDeviceDependencies()
    {
        Guid removedDevice = Guid.NewGuid();
        HsmAdminService service = CreateService([CreateProfile(removedDevice, "Removed", "/tmp/removed.so", true)], out FakeDependencyCleanupService cleanup, out AdminSessionRegistry registry);
        registry.RegisterSyntheticForTesting(removedDevice, "Removed", 1, isReadWrite: false, notes: "tracked");

        AdminConfigurationExportBundle bundle = new()
        {
            Format = "Pkcs11Wrapper.Admin.Configuration",
            SchemaVersion = 1,
            DeviceProfiles =
            [
                CreateProfile(Guid.NewGuid(), "Imported", "/tmp/imported.so", true)
            ]
        };

        await service.ImportConfigurationAsync(new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(bundle, AdminApplicationJsonContext.Default.AdminConfigurationExportBundle)), "import.json", AdminConfigurationImportMode.ReplaceAll, acknowledgeReplaceAll: true);

        IReadOnlyCollection<Guid> retained = Assert.Single(cleanup.CleanupMissingCalls);
        Assert.DoesNotContain(removedDevice, retained);
        Assert.Contains(service.GetSessions(), session => session.DeviceId == removedDevice && !session.IsHealthy);
    }

    private static HsmAdminService CreateService(IReadOnlyList<HsmDeviceProfile> devices, out FakeDependencyCleanupService cleanup, out AdminSessionRegistry registry)
    {
        cleanup = new FakeDependencyCleanupService();
        registry = new AdminSessionRegistry(new AdminSessionRegistryOptions { IdleTimeout = TimeSpan.FromHours(1) });
        return new HsmAdminService(new DeviceProfileService(new InMemoryDeviceProfileStore(devices)), new AuditLogService(new InMemoryAuditLogStore(), new TestActorContext()), registry, new AllowAllAuthorizationService(), cleanup);
    }

    private static HsmDeviceProfile CreateProfile(Guid id, string name, string modulePath, bool isEnabled)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new HsmDeviceProfile(id, name, modulePath, null, null, isEnabled, now, now);
    }

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

    private sealed class InMemoryAuditLogStore : IAuditLogStore
    {
        private readonly List<AdminAuditLogEntry> _entries = [];

        public IReadOnlyList<AdminAuditLogEntry> Entries => _entries;

        public Task AppendAsync(AdminAuditLogEntry entry, CancellationToken cancellationToken = default)
        {
            _entries.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AdminAuditLogEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AdminAuditLogEntry>>(_entries.TakeLast(take).Reverse().ToArray());

        public Task<AuditIntegrityStatus> VerifyIntegrityAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new AuditIntegrityStatus(true, _entries.Count, null, "ok", null));
    }

    private sealed class FakeDependencyCleanupService : IDeviceDependencyCleanupService
    {
        public List<Guid> CleanedDeviceIds { get; } = [];

        public List<IReadOnlyCollection<Guid>> CleanupMissingCalls { get; } = [];

        public Task<DeviceDependencyCleanupSummary> CleanupForDevicesAsync(IReadOnlyCollection<Guid> deviceIds, CancellationToken cancellationToken = default)
        {
            CleanedDeviceIds.AddRange(deviceIds);
            return Task.FromResult(new DeviceDependencyCleanupSummary(0, deviceIds.Count, deviceIds.Count));
        }

        public Task<DeviceDependencyCleanupSummary> CleanupForMissingDevicesAsync(IReadOnlyCollection<Guid> retainedDeviceIds, CancellationToken cancellationToken = default)
        {
            CleanupMissingCalls.Add(retainedDeviceIds.ToArray());
            return Task.FromResult(new DeviceDependencyCleanupSummary(0, 1, 1));
        }
    }

    private sealed class TestActorContext : IAdminActorContext
    {
        public AdminActorInfo GetCurrent()
            => new("tester", "cookie", true, [AdminRoles.Admin], "127.0.0.1", "session-1", "tests");
    }

    private sealed class AllowAllAuthorizationService : IAdminAuthorizationService
    {
        public void DemandAdmin() { }
        public void DemandOperator() { }
        public void DemandViewer() { }
    }
}
