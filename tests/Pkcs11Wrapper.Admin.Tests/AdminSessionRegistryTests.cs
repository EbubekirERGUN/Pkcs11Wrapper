using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class AdminSessionRegistryTests
{
    [Fact]
    public async Task GetSnapshotsExpiresIdleSessionsAndMarksThemExpired()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminSessionRegistry registry = new(new AdminSessionRegistryOptions { IdleTimeout = TimeSpan.FromMinutes(5) }, () => now);
        bool released = false;
        registry.RegisterSyntheticForTesting(Guid.NewGuid(), "Primary", 1, isReadWrite: true, notes: "synthetic", releaseAction: () => released = true);

        now = now.AddMinutes(6);
        AdminSessionSnapshot snapshot = Assert.Single(registry.GetSnapshots());

        Assert.True(released);
        Assert.False(snapshot.IsHealthy);
        Assert.Equal("Expired", snapshot.HealthLabel);
        Assert.Equal("IdleExpired", snapshot.LastOperation);
        Assert.Contains("Idle timeout", snapshot.InvalidationReason, StringComparison.OrdinalIgnoreCase);
        Assert.False(registry.TryGet(snapshot.SessionId, out _));
        Assert.True(await registry.CloseAsync(snapshot.SessionId));
    }

    [Fact]
    public async Task InvalidateAndReleaseForDeviceAsyncOnlyTouchesMatchingDevice()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminSessionRegistry registry = new(new AdminSessionRegistryOptions { IdleTimeout = TimeSpan.FromHours(1) }, () => now);
        Guid targetDevice = Guid.NewGuid();
        Guid otherDevice = Guid.NewGuid();
        registry.RegisterSyntheticForTesting(targetDevice, "Target", 1, isReadWrite: false, notes: "a");
        registry.RegisterSyntheticForTesting(otherDevice, "Other", 2, isReadWrite: false, notes: "b");

        int invalidated = await registry.InvalidateAndReleaseForDeviceAsync(targetDevice, "device changed", "DeviceConfigChanged");
        IReadOnlyList<AdminSessionSnapshot> snapshots = registry.GetSnapshots();

        Assert.Equal(1, invalidated);
        Assert.Contains(snapshots, session => session.DeviceId == targetDevice && !session.IsHealthy && session.HealthLabel == "Invalidated");
        Assert.Contains(snapshots, session => session.DeviceId == otherDevice && session.IsHealthy);
    }
}
