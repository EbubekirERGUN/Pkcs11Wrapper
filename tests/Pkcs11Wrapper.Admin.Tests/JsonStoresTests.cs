using Microsoft.AspNetCore.DataProtection;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Infrastructure;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class JsonStoresTests
{
    [Fact]
    public async Task JsonDeviceProfileStoreRoundTripsProfiles()
    {
        string root = CreateTempDirectory();
        try
        {
            JsonDeviceProfileStore store = new(new AdminStorageOptions { DataRoot = root });
            HsmDeviceProfile profile = new(Guid.NewGuid(), "Test", "/tmp/libpkcs11.so", "token", "notes", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
            await store.SaveAllAsync([profile]);

            IReadOnlyList<HsmDeviceProfile> loaded = await store.GetAllAsync();
            Assert.Single(loaded);
            Assert.Equal(profile.Name, loaded[0].Name);
            Assert.Equal(profile.ModulePath, loaded[0].ModulePath);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task JsonDeviceProfileStoreCreatesBackupOnRewrite()
    {
        string root = CreateTempDirectory();
        try
        {
            AdminStorageOptions options = new() { DataRoot = root };
            JsonDeviceProfileStore store = new(options);
            await store.SaveAllAsync([CreateProfile("Primary")]);
            await store.SaveAllAsync([CreateProfile("Updated")]);

            string path = Path.Combine(root, options.DeviceProfilesFileName);
            Assert.True(File.Exists(path));
            Assert.True(File.Exists(CrashSafeFileStore.GetBackupPath(path)));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task JsonDeviceProfileStoreReportsCorruptionWithBackupPath()
    {
        string root = CreateTempDirectory();
        try
        {
            AdminStorageOptions options = new() { DataRoot = root };
            JsonDeviceProfileStore store = new(options);
            string path = Path.Combine(root, options.DeviceProfilesFileName);
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(path, "{ not-json");

            InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => store.GetAllAsync());
            Assert.Contains("backup", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(CrashSafeFileStore.GetBackupPath(path), exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ProtectedPinStoreDeletesAllEntriesForDevice()
    {
        string root = CreateTempDirectory();
        try
        {
            ProtectedPinStore store = new(new AdminStorageOptions { DataRoot = root }, DataProtectionProvider.Create(new DirectoryInfo(root)));
            Guid removedDevice = Guid.NewGuid();
            Guid retainedDevice = Guid.NewGuid();
            await store.SaveAsync(removedDevice, 1, "login", "1234");
            await store.SaveAsync(removedDevice, 2, "so", "9876");
            await store.SaveAsync(retainedDevice, 1, "login", "4321");

            int removed = await store.DeleteForDeviceAsync(removedDevice);
            IReadOnlyList<ProtectedPinRecord> metadata = await store.GetMetadataAsync();

            Assert.Equal(2, removed);
            Assert.Single(metadata);
            Assert.Equal(retainedDevice, metadata[0].DeviceId);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task JsonAuditStoreReturnsNewestWindowWithStableSequence()
    {
        string root = CreateTempDirectory();
        try
        {
            JsonLineAuditLogStore store = new(new AdminStorageOptions { DataRoot = root });
            for (int i = 0; i < 50; i++)
            {
                await store.AppendAsync(CreateAudit($"target-{i}", $"entry-{i}", DateTimeOffset.UtcNow.AddSeconds(i)));
            }

            IReadOnlyList<AdminAuditLogEntry> logs = await store.ReadRecentAsync(5);
            Assert.Equal(5, logs.Count);
            Assert.Equal("target-49", logs[0].Target);
            Assert.Equal(50, logs[0].Sequence);
            Assert.Equal("target-45", logs[^1].Target);
            Assert.Equal(46, logs[^1].Sequence);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task JsonAuditStoreVerifiesHashChain()
    {
        string root = CreateTempDirectory();
        try
        {
            JsonLineAuditLogStore store = new(new AdminStorageOptions { DataRoot = root });
            await store.AppendAsync(CreateAudit("one", "first", DateTimeOffset.UtcNow.AddMinutes(-1)));
            await store.AppendAsync(CreateAudit("two", "second", DateTimeOffset.UtcNow));

            AuditIntegrityStatus integrity = await store.VerifyIntegrityAsync();

            Assert.True(integrity.IsValid);
            Assert.Equal(2, integrity.CheckedEntries);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task JsonPkcs11TelemetryStoreReturnsNewestWindow()
    {
        string root = CreateTempDirectory();
        try
        {
            JsonLinePkcs11TelemetryStore store = new(new AdminStorageOptions { DataRoot = root });
            for (int i = 0; i < 20; i++)
            {
                await store.AppendAsync(CreateTelemetry($"Operation-{i}", DateTimeOffset.UtcNow.AddSeconds(i)));
            }

            IReadOnlyList<AdminPkcs11TelemetryEntry> logs = await store.ReadRecentAsync(3);

            Assert.Equal(3, logs.Count);
            Assert.Equal("Operation-19", logs[0].OperationName);
            Assert.Equal("Operation-17", logs[^1].OperationName);
            Assert.Equal("Masked", Assert.Single(logs[0].Fields).Classification);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task JsonPkcs11TelemetryStoreRotatesAndPrunesArchives()
    {
        string root = CreateTempDirectory();
        try
        {
            JsonLinePkcs11TelemetryStore store = new(
                new AdminStorageOptions { DataRoot = root },
                new AdminPkcs11TelemetryOptions
                {
                    ActiveFileMaxBytes = 350,
                    MaxArchivedFiles = 2,
                    RetentionDays = 14,
                    ExportMaxEntries = 50
                });

            for (int i = 0; i < 12; i++)
            {
                await store.AppendAsync(CreateTelemetry($"Rotate-{i}", DateTimeOffset.UtcNow.AddSeconds(i), actor: "alice", sessionId: $"trace-{i}"));
            }

            AdminPkcs11TelemetryStorageStatus status = await store.GetStorageStatusAsync();
            IReadOnlyList<AdminPkcs11TelemetryEntry> retained = await store.ReadAllAsync();

            Assert.InRange(status.ArchivedFileCount, 1, 2);
            Assert.InRange(status.RetainedFileCount, 1, 3);
            Assert.True(status.RetainedBytes > 0);
            Assert.Contains(retained, entry => entry.OperationName == "Rotate-11");
            Assert.All(retained, entry => Assert.False(string.IsNullOrWhiteSpace(entry.Actor)));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static HsmDeviceProfile CreateProfile(string name)
        => new(Guid.NewGuid(), name, "/tmp/libpkcs11.so", null, null, true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

    private static AdminAuditLogEntry CreateAudit(string target, string details, DateTimeOffset timestamp)
        => new(Guid.NewGuid(), timestamp, "tester", ["admin"], "cookie", "Device", "Add", target, "Success", details, 0, null, string.Empty, "127.0.0.1", "trace-1", "test-agent", Environment.MachineName);

    private static AdminPkcs11TelemetryEntry CreateTelemetry(string operationName, DateTimeOffset timestamp, string? actor = null, string? sessionId = null)
        => new(
            Guid.NewGuid(),
            timestamp,
            Guid.NewGuid(),
            "Primary",
            operationName,
            $"C_{operationName}",
            "Succeeded",
            1.23,
            "CKR_OK",
            1,
            2,
            0x1082,
            null,
            actor,
            actor is null ? null : "cookie",
            sessionId,
            sessionId,
            [new AdminPkcs11TelemetryField("credential.pin", "Masked", "set(len=8)")]);

    private static string CreateTempDirectory()
    {
        string root = Path.Combine(Path.GetTempPath(), "Pkcs11Wrapper.Admin.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
