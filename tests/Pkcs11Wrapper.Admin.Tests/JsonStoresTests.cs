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

    private static HsmDeviceProfile CreateProfile(string name)
        => new(Guid.NewGuid(), name, "/tmp/libpkcs11.so", null, null, true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

    private static AdminAuditLogEntry CreateAudit(string target, string details, DateTimeOffset timestamp)
        => new(Guid.NewGuid(), timestamp, "tester", ["admin"], "cookie", "Device", "Add", target, "Success", details, 0, null, string.Empty, "127.0.0.1", "trace-1", "test-agent", Environment.MachineName);

    private static string CreateTempDirectory()
    {
        string root = Path.Combine(Path.GetTempPath(), "Pkcs11Wrapper.Admin.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
