using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class Pkcs11TelemetryServiceTests
{
    [Fact]
    public void ListenerMapsOperationEventsIntoTelemetryEntries()
    {
        RecordingStore store = new();
        Pkcs11TelemetryService service = new(store, new StaticActorContext(new AdminActorInfo("alice", "cookie", true, ["admin"], "127.0.0.1", "trace-42", "tests")), new AdminPkcs11TelemetryOptions());
        HsmDeviceProfile device = new(Guid.NewGuid(), "Primary", "/tmp/libpkcs11.so", null, null, true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

        IPkcs11OperationTelemetryListener listener = service.CreateListener(device);
        Pkcs11OperationTelemetryEvent operationEvent = new(
            "SignData",
            "C_Sign",
            Pkcs11OperationTelemetryStatus.Failed,
            TimeSpan.FromMilliseconds(12.5),
            null,
            7,
            19,
            0x00000040,
            new InvalidOperationException("should not be persisted"))
        {
            Fields =
            [
                new Pkcs11OperationTelemetryField("input", Pkcs11TelemetryFieldClassification.LengthOnly, "len=32"),
                new Pkcs11OperationTelemetryField("credential.pin", Pkcs11TelemetryFieldClassification.Masked, "set(len=8)")
            ]
        };

        listener.OnOperationCompleted(in operationEvent);

        AdminPkcs11TelemetryEntry entry = Assert.Single(store.Entries);
        Assert.Equal(device.Id, entry.DeviceId);
        Assert.Equal("Primary", entry.DeviceName);
        Assert.Equal("SignData", entry.OperationName);
        Assert.Equal("C_Sign", entry.NativeOperationName);
        Assert.Equal("Failed", entry.Status);
        Assert.Equal((ulong)7, entry.SlotId);
        Assert.Equal((ulong)19, entry.SessionHandle);
        Assert.Equal((ulong)0x00000040, entry.MechanismType);
        Assert.Equal("InvalidOperationException", entry.ExceptionType);
        Assert.Equal("alice", entry.Actor);
        Assert.Equal("cookie", entry.AuthenticationType);
        Assert.Equal("trace-42", entry.SessionId);
        Assert.Equal("trace-42", entry.CorrelationId);
        Assert.DoesNotContain(entry.Fields, field => field.Value?.Contains("should not be persisted", StringComparison.Ordinal) == true);
        Assert.Contains(entry.Fields, field => field.Name == "input" && field.Classification == "LengthOnly" && field.Value == "len=32");
        Assert.Contains(entry.Fields, field => field.Name == "credential.pin" && field.Classification == "Masked" && field.Value == "set(len=8)");
    }

    [Fact]
    public void ListenerSwallowsStoreFailures()
    {
        Pkcs11TelemetryService service = new(new ThrowingStore(), new StaticActorContext(new AdminActorInfo("alice", "cookie", true, ["admin"], null, "trace-99", null)), new AdminPkcs11TelemetryOptions());
        HsmDeviceProfile device = new(Guid.NewGuid(), "Primary", "/tmp/libpkcs11.so", null, null, true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

        IPkcs11OperationTelemetryListener listener = service.CreateListener(device);
        Pkcs11OperationTelemetryEvent operationEvent = new(
            "OpenSession",
            "C_OpenSession",
            Pkcs11OperationTelemetryStatus.Succeeded,
            TimeSpan.FromMilliseconds(1),
            null,
            1,
            2,
            null,
            null);

        listener.OnOperationCompleted(in operationEvent);
    }

    private sealed class StaticActorContext(AdminActorInfo actor) : IAdminActorContext
    {
        public AdminActorInfo GetCurrent() => actor;
    }

    private sealed class RecordingStore : IPkcs11TelemetryStore
    {
        private readonly List<AdminPkcs11TelemetryEntry> _entries = [];

        public IReadOnlyList<AdminPkcs11TelemetryEntry> Entries => _entries;

        public Task AppendAsync(AdminPkcs11TelemetryEntry entry, CancellationToken cancellationToken = default)
        {
            _entries.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AdminPkcs11TelemetryEntry>>([.. _entries.TakeLast(take).Reverse()]);

        public Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadAllAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AdminPkcs11TelemetryEntry>>([.. _entries.OrderByDescending(entry => entry.TimestampUtc)]);

        public Task<AdminPkcs11TelemetryStorageStatus> GetStorageStatusAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new AdminPkcs11TelemetryStorageStatus(0, 0, 0, 0, 1024, 14, 8, 5000));
    }

    private sealed class ThrowingStore : IPkcs11TelemetryStore
    {
        public Task AppendAsync(AdminPkcs11TelemetryEntry entry, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("boom");

        public Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AdminPkcs11TelemetryEntry>>([]);

        public Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadAllAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AdminPkcs11TelemetryEntry>>([]);

        public Task<AdminPkcs11TelemetryStorageStatus> GetStorageStatusAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new AdminPkcs11TelemetryStorageStatus(0, 0, 0, 0, 1024, 14, 8, 5000));
    }
}
