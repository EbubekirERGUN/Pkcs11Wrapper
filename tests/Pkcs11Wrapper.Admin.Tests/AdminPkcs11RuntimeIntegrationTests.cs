using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class AdminPkcs11RuntimeIntegrationTests
{
    [Fact]
    public void RawPerOperationModuleLifecycleCanInvalidateAnotherSoftHsmSession()
    {
        if (!TryCreateFixture(out FixtureContext? fixture) || fixture is null)
        {
            return;
        }

        using FixtureContext context = fixture;
        Pkcs11Module? owner = null;
        Pkcs11Module? transient = null;
        Pkcs11Session? session = null;

        try
        {
            owner = Pkcs11Module.Load(context.Device.ModulePath);
            owner.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

            transient = Pkcs11Module.Load(context.Device.ModulePath);
            transient.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));
            session = transient.OpenSession(context.SlotId);

            owner.Dispose();
            owner = null;

            Pkcs11Exception exception = Assert.Throws<Pkcs11Exception>(() => session!.Dispose());
            session = null;
            Assert.Equal((nuint)0x190u, exception.Result.Value);
            Assert.Equal("C_CloseSession", exception.Operation);
        }
        finally
        {
            session?.Dispose();
            transient?.Dispose();
            owner?.Dispose();
        }
    }

    [Fact]
    public async Task HsmAdminServiceKeepsTrackedSessionsStableWhileKeysPageLoads()
    {
        if (!TryCreateFixture(out FixtureContext? fixture) || fixture is null)
        {
            return;
        }

        await using FixtureContext context = fixture;
        using AdminPkcs11Runtime runtime = new();
        await using AdminSessionRegistry registry = new(new AdminSessionRegistryOptions { IdleTimeout = TimeSpan.FromHours(1) });
        HsmAdminService service = CreateService(context.Device, runtime, registry);

        AdminSessionSnapshot tracked = await service.OpenSessionAsync(context.Device.Id, context.SlotId.Value, readWrite: false, context.UserPin);
        try
        {
            HsmKeyObjectPage page = await service.GetKeyPageAsync(
                context.Device.Id,
                context.SlotId.Value,
                new KeyObjectPageRequest
                {
                    SortMode = "handle",
                    PageSize = 10
                },
                context.UserPin);

            Assert.NotEmpty(page.Items);
            HsmKeyObjectSummary first = page.Items.First();
            HsmObjectDetail detail = await service.GetObjectDetailAsync(context.Device.Id, context.SlotId.Value, first.Handle, context.UserPin);

            Assert.Equal(first.Handle, detail.Handle);
            Assert.Contains(service.GetSessions(), snapshot => snapshot.SessionId == tracked.SessionId && snapshot.IsHealthy);
        }
        finally
        {
            bool closed = await service.CloseSessionAsync(tracked.SessionId);
            Assert.True(closed);
        }
    }

    [Fact]
    public void AdminPkcs11RuntimeKeepsSecondLeaseSessionClosableAfterFirstLeaseEnds()
    {
        if (!TryCreateFixture(out FixtureContext? fixture) || fixture is null)
        {
            return;
        }

        using FixtureContext context = fixture;
        using AdminPkcs11Runtime runtime = new();

        AdminPkcs11ModuleLease? firstLease = null;
        AdminPkcs11ModuleLease? secondLease = null;
        Pkcs11Session? firstSession = null;
        Pkcs11Session? secondSession = null;

        try
        {
            firstLease = runtime.Acquire(context.Device);
            firstSession = firstLease.Module.OpenSession(context.SlotId);

            secondLease = runtime.Acquire(context.Device);
            secondSession = secondLease.Module.OpenSession(context.SlotId);

            firstSession.Dispose();
            firstSession = null;
            firstLease.Dispose();
            firstLease = null;

            Exception? closeException = Record.Exception(() => secondSession!.Dispose());
            secondSession = null;
            Assert.Null(closeException);
        }
        finally
        {
            secondSession?.Dispose();
            secondLease?.Dispose();
            firstSession?.Dispose();
            firstLease?.Dispose();
        }
    }

    private static HsmAdminService CreateService(HsmDeviceProfile device, AdminPkcs11Runtime runtime, AdminSessionRegistry registry)
        => new(
            new DeviceProfileService(new InMemoryDeviceProfileStore([device])),
            new AuditLogService(new InMemoryAuditLogStore(), new TestActorContext()),
            registry,
            new AllowAllAuthorizationService(),
            runtime);

    private static bool TryCreateFixture(out FixtureContext? fixture)
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? tokenLabel = Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL");
        string? userPin = Environment.GetEnvironmentVariable("PKCS11_USER_PIN");
        if (string.IsNullOrWhiteSpace(modulePath) || string.IsNullOrWhiteSpace(tokenLabel) || string.IsNullOrWhiteSpace(userPin))
        {
            fixture = null;
            return false;
        }

        using Pkcs11Module module = Pkcs11Module.Load(modulePath);
        module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

        int slotCount = module.GetSlotCount(tokenPresentOnly: false);
        Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
        if (!module.TryGetSlots(slots, out int written, tokenPresentOnly: false))
        {
            throw new InvalidOperationException("Failed to enumerate SoftHSM fixture slots for admin runtime tests.");
        }

        for (int i = 0; i < written; i++)
        {
            if (module.TryGetTokenInfo(slots[i], out Pkcs11TokenInfo tokenInfo)
                && string.Equals(tokenInfo.Label.Trim(), tokenLabel, StringComparison.Ordinal))
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                fixture = new FixtureContext(
                    new HsmDeviceProfile(Guid.NewGuid(), "Fixture SoftHSM", modulePath, tokenLabel, null, true, now, now),
                    slots[i],
                    userPin);
                return true;
            }
        }

        throw new InvalidOperationException($"SoftHSM fixture token '{tokenLabel}' was not found.");
    }

    private sealed class FixtureContext(HsmDeviceProfile device, Pkcs11SlotId slotId, string userPin) : IAsyncDisposable, IDisposable
    {
        public HsmDeviceProfile Device { get; } = device;
        public Pkcs11SlotId SlotId { get; } = slotId;
        public string UserPin { get; } = userPin;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
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
        public void DemandAdmin() { }
        public void DemandOperator() { }
        public void DemandViewer() { }
    }
}
