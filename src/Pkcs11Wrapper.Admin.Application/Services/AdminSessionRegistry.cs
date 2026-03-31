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

    public bool Touch(Guid sessionId, string operation)
    {
        if (_sessions.TryGetValue(sessionId, out TrackedSession? tracked))
        {
            tracked.LastOperation = operation;
            tracked.LastTouchedUtc = DateTimeOffset.UtcNow;
            return true;
        }

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
            return tracked.ToSnapshot(true, info.State.ToString(), tracked.Notes);
        }
        catch (Exception ex)
        {
            return tracked.ToSnapshot(false, "Unavailable", ex.Message);
        }
    }

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

        public AdminSessionSnapshot ToSnapshot(bool isHealthy = true, string? state = null, string? notesOverride = null)
        {
            string effectiveState = state ?? Session.GetInfo().State.ToString();
            return new AdminSessionSnapshot(Id, DeviceId, DeviceName, Session.SlotId.Value, IsReadWrite, effectiveState, OpenedUtc, LastTouchedUtc, LastOperation, isHealthy, notesOverride ?? Notes);
        }

        public ValueTask DisposeAsync()
        {
            Session.Dispose();
            Module.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
