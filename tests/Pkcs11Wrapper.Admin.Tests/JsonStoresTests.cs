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
    public async Task JsonAuditStoreReturnsNewestFirst()
    {
        string root = CreateTempDirectory();
        try
        {
            JsonLineAuditLogStore store = new(new AdminStorageOptions { DataRoot = root });
            await store.AppendAsync(CreateAudit("one", "first", DateTimeOffset.UtcNow.AddMinutes(-1)));
            await store.AppendAsync(CreateAudit("two", "second", DateTimeOffset.UtcNow));

            IReadOnlyList<AdminAuditLogEntry> logs = await store.ReadRecentAsync(10);
            Assert.Equal(2, logs.Count);
            Assert.Equal("two", logs[0].Target);
            Assert.Equal("one", logs[1].Target);
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

    private static AdminAuditLogEntry CreateAudit(string target, string details, DateTimeOffset timestamp)
        => new(Guid.NewGuid(), timestamp, "tester", ["admin"], "cookie", "Device", "Add", target, "Success", details, 0, null, string.Empty, "127.0.0.1", "trace-1", "test-agent", Environment.MachineName);

    private static string CreateTempDirectory()
    {
        string root = Path.Combine(Path.GetTempPath(), "Pkcs11Wrapper.Admin.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
