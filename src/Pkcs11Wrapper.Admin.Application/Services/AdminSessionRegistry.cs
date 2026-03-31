using System.Collections.Concurrent;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class AdminSessionRegistry
{
    private readonly ConcurrentDictionary<Guid, TrackedSession> _sessions = new();

    public AdminSessionSnapshot Register(Guid deviceId, string deviceName, Pkcs11Module module, Pkcs11Session session, bool isReadWrite, string notes)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Guid id = Guid.NewGuid();
        TrackedSession tracked = new(id, deviceId, deviceName, module, session, isReadWrite, now, now, "Opened", notes);
        _sessions[id] = tracked;
        return tracked.ToSnapshot();
    }

    public IReadOnlyList<AdminSessionSnapshot> GetSnapshots()
        => _sessions.Values
            .Select(UpdateSnapshot)
            .OrderByDescending(x => x.LastTouchedUtc)
            .ToArray();

    public bool TryTouch(Guid sessionId, string operation)
    {
        if (_sessions.TryGetValue(sessionId, out TrackedSession? tracked))
        {
            tracked.LastOperation = operation;
            tracked.LastTouchedUtc = DateTimeOffset.UtcNow;
            tracked.InvalidationReason = null;
            return true;
        }

        return false;
    }

    public bool TryGet(Guid sessionId, out AdminTrackedSession? session)
    {
        if (_sessions.TryGetValue(sessionId, out TrackedSession? tracked))
        {
            session = new AdminTrackedSession(tracked.Module, tracked.Session, tracked.DeviceId, tracked.DeviceName, tracked.IsReadWrite, tracked.Notes);
            return true;
        }

        session = null;
        return false;
    }

    public async Task<bool> CloseAsync(Guid sessionId)
    {
        if (_sessions.TryRemove(sessionId, out TrackedSession? tracked))
        {
            await tracked.DisposeAsync();
            return true;
        }

        return false;
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

    private AdminSessionSnapshot UpdateSnapshot(TrackedSession tracked)
    {
        try
        {
            Pkcs11SessionInfo info = tracked.Session.GetInfo();
            tracked.InvalidationReason = null;
            return tracked.ToSnapshot(info, true, tracked.Notes);
        }
        catch (Exception ex)
        {
            tracked.InvalidationReason ??= ex.Message;
            return tracked.ToSnapshot(default, false, ex.Message);
        }
    }

    public void MarkInvalidated(Guid sessionId, string reason, string operation)
    {
        if (_sessions.TryGetValue(sessionId, out TrackedSession? tracked))
        {
            tracked.LastOperation = operation;
            tracked.LastTouchedUtc = DateTimeOffset.UtcNow;
            tracked.InvalidationReason = reason;
        }
    }

    public void MarkInvalidatedForSlot(Guid deviceId, nuint slotId, string reason, string operation)
    {
        foreach (TrackedSession tracked in _sessions.Values)
        {
            if (tracked.DeviceId == deviceId && tracked.Session.SlotId.Value == slotId)
            {
                tracked.LastOperation = operation;
                tracked.LastTouchedUtc = DateTimeOffset.UtcNow;
                tracked.InvalidationReason = reason;
            }
        }
    }

    public sealed record AdminTrackedSession(
        Pkcs11Module Module,
        Pkcs11Session Session,
        Guid DeviceId,
        string DeviceName,
        bool IsReadWrite,
        string Notes);

    private sealed class TrackedSession(
        Guid id,
        Guid deviceId,
        string deviceName,
        Pkcs11Module module,
        Pkcs11Session session,
        bool isReadWrite,
        DateTimeOffset openedUtc,
        DateTimeOffset lastTouchedUtc,
        string lastOperation,
        string notes) : IAsyncDisposable
    {
        public Guid Id { get; } = id;
        public Guid DeviceId { get; } = deviceId;
        public string DeviceName { get; } = deviceName;
        public Pkcs11Module Module { get; } = module;
        public Pkcs11Session Session { get; } = session;
        public bool IsReadWrite { get; } = isReadWrite;
        public DateTimeOffset OpenedUtc { get; } = openedUtc;
        public DateTimeOffset LastTouchedUtc { get; set; } = lastTouchedUtc;
        public string LastOperation { get; set; } = lastOperation;
        public string Notes { get; } = notes;
        public string? InvalidationReason { get; set; }

        public AdminSessionSnapshot ToSnapshot(Pkcs11SessionInfo info = default, bool isHealthy = true, string? notesOverride = null)
        {
            bool isUserAuthenticated = info.State is Pkcs11SessionState.ReadOnlyUser or Pkcs11SessionState.ReadWriteUser;
            bool isSoAuthenticated = info.State is Pkcs11SessionState.ReadWriteSecurityOfficer;
            string state = isHealthy ? info.State.ToString() : "Unavailable";
            string flags = isHealthy ? info.Flags.ToString() : "Unavailable";
            nuint deviceError = isHealthy ? info.DeviceError : 0;
            string healthLabel = isHealthy ? "Healthy" : InvalidationReason is null ? "Broken" : "Invalidated";
            bool canLogin = isHealthy && !isUserAuthenticated && !isSoAuthenticated;
            bool canLogout = isHealthy && (isUserAuthenticated || isSoAuthenticated);
            bool canCancel = isHealthy;
            return new AdminSessionSnapshot(Id, DeviceId, DeviceName, Session.SlotId.Value, IsReadWrite, state, flags, deviceError, isUserAuthenticated, isSoAuthenticated, OpenedUtc, LastTouchedUtc, LastOperation, isHealthy, notesOverride ?? Notes, healthLabel, InvalidationReason, canLogin, canLogout, canCancel, true, true);
        }

        public ValueTask DisposeAsync()
        {
            Session.Dispose();
            Module.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
