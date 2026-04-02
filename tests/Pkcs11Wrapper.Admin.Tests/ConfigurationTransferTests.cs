using System.Text.Json;
using Pkcs11Wrapper.Admin.Application;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class ConfigurationTransferTests
{
    [Fact]
    public async Task ExportConfigurationAsyncIncludesDeviceProfilesAndExcludedSections()
    {
        HsmAdminService service = CreateService(
        [
            CreateProfile(
                Guid.NewGuid(),
                "Primary HSM",
                "/usr/lib/libpkcs11.so",
                new HsmDeviceVendorMetadata("thales", "Thales", "luna-standard", "Luna / standard PKCS#11"))
        ]);

        AdminConfigurationExportBundle bundle = await service.ExportConfigurationAsync();

        Assert.Equal("Pkcs11Wrapper.Admin.Configuration", bundle.Format);
        Assert.Equal(1, bundle.SchemaVersion);
        Assert.Contains("DeviceProfiles", bundle.IncludedSections);
        Assert.Contains("AdminUsers", bundle.ExcludedSections);
        Assert.Contains("ProtectedPinCache", bundle.ExcludedSections);
        Assert.Single(bundle.DeviceProfiles);
        Assert.Equal("Primary HSM", bundle.DeviceProfiles[0].Name);
        Assert.Equal("Thales", bundle.DeviceProfiles[0].Vendor?.VendorName);
        Assert.Equal("luna-standard", bundle.DeviceProfiles[0].Vendor?.ProfileId);
    }

    [Fact]
    public async Task ImportConfigurationAsyncMergeAddsAndUpdatesDeviceProfiles()
    {
        Guid existingId = Guid.NewGuid();
        HsmAdminService service = CreateService(
        [
            CreateProfile(existingId, "Primary HSM", "/usr/lib/original.so")
        ]);

        AdminConfigurationExportBundle bundle = new()
        {
            DeviceProfiles =
            [
                CreateProfile(existingId, "Primary HSM", "/opt/updated.so"),
                CreateProfile(Guid.NewGuid(), "Backup HSM", "/opt/backup.so")
            ]
        };

        AdminConfigurationImportResult result = await service.ImportConfigurationAsync(CreateBundleStream(bundle), "import.json", AdminConfigurationImportMode.Merge, acknowledgeReplaceAll: false);
        IReadOnlyList<HsmDeviceProfile> devices = await service.GetDevicesAsync();

        Assert.Equal(2, devices.Count);
        Assert.Equal(1, result.AddedDeviceProfileCount);
        Assert.Equal(1, result.UpdatedDeviceProfileCount);
        Assert.Contains(devices, device => device.Name == "Primary HSM" && device.ModulePath == "/opt/updated.so");
        Assert.Contains(devices, device => device.Name == "Backup HSM");
    }

    [Fact]
    public async Task ImportConfigurationAsyncReplaceAllRequiresAcknowledgement()
    {
        HsmAdminService service = CreateService(
        [
            CreateProfile(Guid.NewGuid(), "Primary HSM", "/usr/lib/original.so")
        ]);

        AdminConfigurationExportBundle bundle = new()
        {
            DeviceProfiles =
            [
                CreateProfile(Guid.NewGuid(), "Imported HSM", "/opt/imported.so")
            ]
        };

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.ImportConfigurationAsync(CreateBundleStream(bundle), "import.json", AdminConfigurationImportMode.ReplaceAll, acknowledgeReplaceAll: false));
        Assert.Contains("explicit acknowledgement", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ImportConfigurationAsyncRejectsConflictingDeviceNameDuringMerge()
    {
        HsmAdminService service = CreateService(
        [
            CreateProfile(Guid.NewGuid(), "Primary HSM", "/usr/lib/original.so")
        ]);

        AdminConfigurationExportBundle bundle = new()
        {
            DeviceProfiles =
            [
                CreateProfile(Guid.NewGuid(), "Primary HSM", "/opt/imported.so")
            ]
        };

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.ImportConfigurationAsync(CreateBundleStream(bundle), "import.json", AdminConfigurationImportMode.Merge, acknowledgeReplaceAll: false));
        Assert.Contains("conflicting device name", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static MemoryStream CreateBundleStream(AdminConfigurationExportBundle bundle)
        => new(JsonSerializer.SerializeToUtf8Bytes(bundle, AdminApplicationJsonContext.Default.AdminConfigurationExportBundle));

    private static HsmAdminService CreateService(IReadOnlyList<HsmDeviceProfile> devices)
    {
        InMemoryDeviceProfileStore deviceStore = new(devices);
        DeviceProfileService deviceProfiles = new(deviceStore);
        AuditLogService auditLog = new(new InMemoryAuditLogStore(), new TestActorContext());
        return new HsmAdminService(deviceProfiles, auditLog, new AdminSessionRegistry(), new AllowAllAuthorizationService());
    }

    private static HsmDeviceProfile CreateProfile(Guid id, string name, string modulePath, HsmDeviceVendorMetadata? vendor = null)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new HsmDeviceProfile(id, name, modulePath, null, null, true, now, now, vendor);
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
