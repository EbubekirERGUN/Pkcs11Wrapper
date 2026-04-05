using System.Collections.Concurrent;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class AdminSessionRegistry(AdminSessionRegistryOptions? options = null, Func<DateTimeOffset>? clock = null) : IAsyncDisposable
{
    private readonly ConcurrentDictionary<Guid, TrackedSession> _sessions = new();
    private readonly TimeSpan _idleTimeout = (options ?? new()).IdleTimeout <= TimeSpan.Zero ? TimeSpan.FromMinutes(20) : (options ?? new()).IdleTimeout;
    private readonly Func<DateTimeOffset> _clock = clock ?? (() => DateTimeOffset.UtcNow);

    public AdminSessionSnapshot Register(Guid deviceId, string deviceName, Pkcs11Module module, Pkcs11Session session, bool isReadWrite, string notes)
    {
        DateTimeOffset now = _clock();
        Guid id = Guid.NewGuid();
        TrackedSession tracked = new(id, deviceId, deviceName, session.SlotId.Value, module, session, isReadWrite, now, now, "Opened", notes, () =>
        {
            session.Dispose();
            module.Dispose();
        });
        _sessions[id] = tracked;
        return UpdateSnapshot(tracked);
    }

    public AdminSessionSnapshot RegisterSyntheticForTesting(Guid deviceId, string deviceName, nuint slotId, bool isReadWrite, string notes, Func<Pkcs11SessionInfo>? infoFactory = null, Action? releaseAction = null, DateTimeOffset? openedUtc = null, DateTimeOffset? lastTouchedUtc = null)
    {
        DateTimeOffset now = _clock();
        Guid id = Guid.NewGuid();
        TrackedSession tracked = new(id, deviceId, deviceName, slotId, null, null, isReadWrite, openedUtc ?? now, lastTouchedUtc ?? now, "Opened", notes, releaseAction, infoFactory ?? (() => default));
        _sessions[id] = tracked;
        return UpdateSnapshot(tracked);
    }

    public IReadOnlyList<AdminSessionSnapshot> GetSnapshots()
    {
        ExpireIdleSessions();
        return _sessions.Values
            .Select(UpdateSnapshot)
            .OrderByDescending(x => x.LastTouchedUtc)
            .ToArray();
    }

    public AdminSessionRegistryMetricsSnapshot GetMetricsSnapshot()
    {
        IReadOnlyList<AdminSessionSnapshot> snapshots = GetSnapshots();
        return new AdminSessionRegistryMetricsSnapshot(
            Healthy: snapshots.Count(static snapshot => snapshot.IsHealthy && string.Equals(snapshot.HealthLabel, "Healthy", StringComparison.Ordinal)),
            Broken: snapshots.Count(static snapshot => string.Equals(snapshot.HealthLabel, "Broken", StringComparison.Ordinal)),
            Expired: snapshots.Count(static snapshot => string.Equals(snapshot.HealthLabel, "Expired", StringComparison.Ordinal)),
            Invalidated: snapshots.Count(static snapshot => string.Equals(snapshot.HealthLabel, "Invalidated", StringComparison.Ordinal)));
    }

    public bool TryTouch(Guid sessionId, string operation)
    {
        ExpireIdleSessions();
        if (_sessions.TryGetValue(sessionId, out TrackedSession? tracked) && !tracked.ResourcesReleased)
        {
            tracked.LastOperation = operation;
            tracked.LastTouchedUtc = _clock();
            tracked.InvalidationReason = null;
            return true;
        }

        return false;
    }

    public bool TryGet(Guid sessionId, out AdminTrackedSession? session)
    {
        ExpireIdleSessions();
        if (_sessions.TryGetValue(sessionId, out TrackedSession? tracked) && !tracked.ResourcesReleased && tracked.Module is not null && tracked.Session is not null)
        {
            session = new AdminTrackedSession(tracked.Module, tracked.Session, tracked.DeviceId, tracked.DeviceName, tracked.IsReadWrite, tracked.Notes);
            return true;
        }

        session = null;
        return false;
    }

    public Task<bool> CloseAsync(Guid sessionId)
    {
        if (_sessions.TryRemove(sessionId, out TrackedSession? tracked))
        {
            tracked.ReleaseIfNeeded();
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    public async Task<int> CloseAllAsync()
    {
        Guid[] ids = _sessions.Keys.ToArray();
        int closed = 0;
        foreach (Guid id in ids)
        {
            if (await CloseAsync(id))
            {
                closed++;
            }
        }

        return closed;
    }

    public Task<int> InvalidateAndReleaseForDeviceAsync(Guid deviceId, string reason, string operation)
        => InvalidateAndReleaseAsync(tracked => tracked.DeviceId == deviceId, reason, operation);

    public Task<int> InvalidateAndReleaseMissingDevicesAsync(IReadOnlyCollection<Guid> retainedDeviceIds, string reason, string operation)
    {
        HashSet<Guid> retained = [.. retainedDeviceIds];
        return InvalidateAndReleaseAsync(tracked => !retained.Contains(tracked.DeviceId), reason, operation);
    }

    public void MarkInvalidated(Guid sessionId, string reason, string operation)
    {
        if (_sessions.TryGetValue(sessionId, out TrackedSession? tracked))
        {
            tracked.LastOperation = operation;
            tracked.LastTouchedUtc = _clock();
            tracked.InvalidationReason = reason;
        }
    }

    public void MarkInvalidatedForSlot(Guid deviceId, nuint slotId, string reason, string operation)
    {
        foreach (TrackedSession tracked in _sessions.Values)
        {
            if (tracked.DeviceId == deviceId && tracked.SlotId == slotId)
            {
                tracked.LastOperation = operation;
                tracked.LastTouchedUtc = _clock();
                tracked.InvalidationReason = reason;
            }
        }
    }

    public async ValueTask DisposeAsync()
        => _ = await CloseAllAsync();

    private Task<int> InvalidateAndReleaseAsync(Func<TrackedSession, bool> predicate, string reason, string operation)
    {
        int count = 0;
        DateTimeOffset now = _clock();
        foreach (TrackedSession tracked in _sessions.Values)
        {
            if (!predicate(tracked))
            {
                continue;
            }

            tracked.LastOperation = operation;
            tracked.LastTouchedUtc = now;
            tracked.InvalidationReason = reason;
            tracked.ReleaseIfNeeded();
            count++;
        }

        return Task.FromResult(count);
    }

    private void ExpireIdleSessions()
    {
        DateTimeOffset now = _clock();
        foreach (TrackedSession tracked in _sessions.Values)
        {
            if (tracked.ResourcesReleased)
            {
                continue;
            }

            if (now - tracked.LastTouchedUtc >= _idleTimeout)
            {
                tracked.LastOperation = "IdleExpired";
                tracked.LastTouchedUtc = now;
                tracked.InvalidationReason = $"Idle timeout exceeded after {_idleTimeout:g}.";
                tracked.ReleaseIfNeeded();
            }
        }
    }

    private AdminSessionSnapshot UpdateSnapshot(TrackedSession tracked)
    {
        if (tracked.ResourcesReleased)
        {
            string healthLabel = string.Equals(tracked.LastOperation, "IdleExpired", StringComparison.Ordinal) ? "Expired" : "Invalidated";
            return tracked.ToUnavailableSnapshot(isHealthyOverride: false, healthLabelOverride: healthLabel, invalidationReasonOverride: tracked.InvalidationReason, notesOverride: tracked.Notes);
        }

        try
        {
            Pkcs11SessionInfo info = tracked.GetInfo();
            tracked.InvalidationReason = null;
            return tracked.ToHealthySnapshot(info);
        }
        catch (Exception ex)
        {
            tracked.InvalidationReason ??= ex.Message;
            return tracked.ToUnavailableSnapshot(isHealthyOverride: false, healthLabelOverride: "Broken", invalidationReasonOverride: tracked.InvalidationReason, notesOverride: ex.Message);
        }
    }

    public sealed record AdminTrackedSession(
        Pkcs11Module Module,
        Pkcs11Session Session,
        Guid DeviceId,
        string DeviceName,
        bool IsReadWrite,
        string Notes);

    public sealed record AdminSessionRegistryMetricsSnapshot(
        int Healthy,
        int Broken,
        int Expired,
        int Invalidated);

    private sealed class TrackedSession(
        Guid id,
        Guid deviceId,
        string deviceName,
        nuint slotId,
        Pkcs11Module? module,
        Pkcs11Session? session,
        bool isReadWrite,
        DateTimeOffset openedUtc,
        DateTimeOffset lastTouchedUtc,
        string lastOperation,
        string notes,
        Action? releaseAction,
        Func<Pkcs11SessionInfo>? infoFactory = null)
    {
        public Guid Id { get; } = id;
        public Guid DeviceId { get; } = deviceId;
        public string DeviceName { get; } = deviceName;
        public nuint SlotId { get; } = slotId;
        public Pkcs11Module? Module { get; } = module;
        public Pkcs11Session? Session { get; } = session;
        public bool IsReadWrite { get; } = isReadWrite;
        public DateTimeOffset OpenedUtc { get; } = openedUtc;
        public DateTimeOffset LastTouchedUtc { get; set; } = lastTouchedUtc;
        public string LastOperation { get; set; } = lastOperation;
        public string Notes { get; } = notes;
        public string? InvalidationReason { get; set; }
        public bool ResourcesReleased { get; private set; }

        public Pkcs11SessionInfo GetInfo()
            => infoFactory is not null
                ? infoFactory()
                : Session?.GetInfo() ?? throw new InvalidOperationException("Tracked session resources were already released.");

        public void ReleaseIfNeeded()
        {
            if (ResourcesReleased)
            {
                return;
            }

            releaseAction?.Invoke();
            ResourcesReleased = true;
        }

        public AdminSessionSnapshot ToHealthySnapshot(Pkcs11SessionInfo info)
        {
            bool isUserAuthenticated = info.State is Pkcs11SessionState.ReadOnlyUser or Pkcs11SessionState.ReadWriteUser;
            bool isSoAuthenticated = info.State is Pkcs11SessionState.ReadWriteSecurityOfficer;
            return new AdminSessionSnapshot(Id, DeviceId, DeviceName, SlotId, IsReadWrite, info.State.ToString(), info.Flags.ToString(), info.DeviceError, isUserAuthenticated, isSoAuthenticated, OpenedUtc, LastTouchedUtc, LastOperation, true, Notes, "Healthy", null, !isUserAuthenticated && !isSoAuthenticated, isUserAuthenticated || isSoAuthenticated, true, true, true);
        }

        public AdminSessionSnapshot ToUnavailableSnapshot(bool isHealthyOverride, string healthLabelOverride, string? invalidationReasonOverride, string? notesOverride)
            => new(Id, DeviceId, DeviceName, SlotId, IsReadWrite, "Unavailable", "Unavailable", 0, false, false, OpenedUtc, LastTouchedUtc, LastOperation, isHealthyOverride, notesOverride ?? Notes, healthLabelOverride, invalidationReasonOverride, false, false, false, true, false);
    }
}
