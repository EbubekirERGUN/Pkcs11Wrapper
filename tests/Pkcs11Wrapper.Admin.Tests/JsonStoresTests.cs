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
            HsmDeviceProfile profile = new(
                Guid.NewGuid(),
                "Test",
                "/tmp/libpkcs11.so",
                "token",
                "notes",
                true,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                new HsmDeviceVendorMetadata("thales", "Thales", "luna-standard", "Luna / standard PKCS#11"));
            await store.SaveAllAsync([profile]);

            IReadOnlyList<HsmDeviceProfile> loaded = await store.GetAllAsync();
            Assert.Single(loaded);
            Assert.Equal(profile.Name, loaded[0].Name);
            Assert.Equal(profile.ModulePath, loaded[0].ModulePath);
            Assert.Equal("Thales", loaded[0].Vendor?.VendorName);
            Assert.Equal("luna-standard", loaded[0].Vendor?.ProfileId);
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
    public void CrashSafeFileStorePromoteTempFileFallsBackToReplaceWhenDestinationAppearsBeforeMove()
    {
        string root = CreateTempDirectory();
        try
        {
            string path = Path.Combine(root, "race.json");
            string tempPath = $"{path}.tmp-{Guid.NewGuid():N}";
            File.WriteAllText(tempPath, "new");

            CrashSafeFileStore.PromoteTempFile(
                path,
                tempPath,
                onBeforeMove: () => File.WriteAllText(path, "old"));

            Assert.Equal("new", File.ReadAllText(path));
            Assert.Equal("old", File.ReadAllText(CrashSafeFileStore.GetBackupPath(path)));
            Assert.False(File.Exists(tempPath));
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
    public async Task JsonAuditStoreWritesBomlessUtf8Jsonl()
    {
        string root = CreateTempDirectory();
        try
        {
            AdminStorageOptions options = new() { DataRoot = root };
            JsonLineAuditLogStore store = new(options);
            await store.AppendAsync(CreateAudit("fresh-stack", "first-entry", DateTimeOffset.UtcNow));

            byte[] bytes = await File.ReadAllBytesAsync(Path.Combine(root, options.AuditLogFileName));

            Assert.False(StartsWithUtf8Bom(bytes));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task JsonAuditStoreHandlesLegacyBomPrefixedFirstEntryAcrossRestart()
    {
        string root = CreateTempDirectory();
        try
        {
            AdminStorageOptions options = new() { DataRoot = root };
            JsonLineAuditLogStore initialStore = new(options);
            await initialStore.AppendAsync(CreateAudit("cihaz-İstanbul", "İlk giriş 🔐", DateTimeOffset.UtcNow.AddMinutes(-1)));

            string path = Path.Combine(root, options.AuditLogFileName);
            PrependUtf8Bom(path);

            JsonLineAuditLogStore restartedStore = new(options);
            IReadOnlyList<AdminAuditLogEntry> beforeAppend = await restartedStore.ReadRecentAsync(1);
            await restartedStore.AppendAsync(CreateAudit("cihaz-Ankara", "İkinci giriş", DateTimeOffset.UtcNow));
            IReadOnlyList<AdminAuditLogEntry> afterAppend = await restartedStore.ReadRecentAsync(2);
            AuditIntegrityStatus integrity = await restartedStore.VerifyIntegrityAsync();

            Assert.Single(beforeAppend);
            Assert.Equal("cihaz-İstanbul", beforeAppend[0].Target);
            Assert.Equal("İlk giriş 🔐", beforeAppend[0].Details);
            Assert.Equal(1, beforeAppend[0].Sequence);

            Assert.Equal(2, afterAppend.Count);
            Assert.Equal("cihaz-Ankara", afterAppend[0].Target);
            Assert.Equal(2, afterAppend[0].Sequence);
            Assert.Equal("cihaz-İstanbul", afterAppend[1].Target);
            Assert.Equal(1, afterAppend[1].Sequence);

            Assert.True(integrity.IsValid);
            Assert.Equal(2, integrity.CheckedEntries);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task JsonAuditStoreReadRecentPreservesUtf8Content()
    {
        string root = CreateTempDirectory();
        try
        {
            AdminStorageOptions options = new() { DataRoot = root };
            JsonLineAuditLogStore store = new(options);
            await store.AppendAsync(CreateAudit("profil-şifre", "Operatör parolayı güncelledi 🔐", DateTimeOffset.UtcNow));

            JsonLineAuditLogStore restartedStore = new(options);
            IReadOnlyList<AdminAuditLogEntry> logs = await restartedStore.ReadRecentAsync(1);

            Assert.Single(logs);
            Assert.Equal("profil-şifre", logs[0].Target);
            Assert.Equal("Operatör parolayı güncelledi 🔐", logs[0].Details);
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

    private static void PrependUtf8Bom(string path)
    {
        byte[] payload = File.ReadAllBytes(path);
        if (StartsWithUtf8Bom(payload))
        {
            return;
        }

        byte[] withBom = new byte[payload.Length + 3];
        withBom[0] = 0xEF;
        withBom[1] = 0xBB;
        withBom[2] = 0xBF;
        Buffer.BlockCopy(payload, 0, withBom, 3, payload.Length);
        File.WriteAllBytes(path, withBom);
    }

    private static bool StartsWithUtf8Bom(byte[] bytes)
        => bytes.Length >= 3
            && bytes[0] == 0xEF
            && bytes[1] == 0xBB
            && bytes[2] == 0xBF;

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
