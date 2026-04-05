using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Observability;
using Pkcs11Wrapper.CryptoApi.Operations;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.CryptoApi.Runtime;

public sealed class CryptoApiPkcs11Runtime(IOptions<CryptoApiRuntimeOptions> runtimeOptions, CryptoApiMetrics? metrics = null) : ICryptoApiPkcs11RuntimeMetricsSource, IDisposable
{
    private static readonly nuint CkrFunctionFailed = 0x00000006u;
    private static readonly nuint CkrUserAlreadyLoggedIn = 0x00000100u;
    private readonly ConcurrentDictionary<string, BackendRuntime> _namedBackends = new(StringComparer.OrdinalIgnoreCase);
    private readonly CryptoApiMetrics? _metrics = metrics;
    private readonly BackendRuntime _defaultBackend = new(new BackendConfiguration(
        Name: "default",
        ModulePath: runtimeOptions.Value.ModulePath?.Trim(),
        UserPin: runtimeOptions.Value.UserPin?.Trim(),
        MaxRetainedSessionsPerSlot: Math.Max(runtimeOptions.Value.MaxRetainedSessionsPerSlot, 0)),
        metrics);
    private bool _disposed;

    public bool HasNamedBackends
        => runtimeOptions.Value.Backends.Any(static backend => backend.Enabled);

    public IReadOnlyList<string> GetNamedBackendNames()
        => runtimeOptions.Value.Backends
            .Where(static backend => backend.Enabled)
            .Select(backend => CryptoApiConfiguredRouteRegistry.NormalizeMachineName(backend.Name, nameof(backend.Name)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static backend => backend, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public Pkcs11Module GetInitializedModule(string? deviceRoute = null)
        => ResolveBackend(deviceRoute).GetInitializedModule();

    internal CryptoApiPooledSessionLease RentSession(string? deviceRoute, Pkcs11SlotId slotId)
    {
        ThrowIfDisposed();
        return ResolveBackend(deviceRoute).RentSession(slotId);
    }

    public IReadOnlyList<CryptoApiPkcs11SessionPoolMetricsSnapshot> GetSessionPoolMetricsSnapshots()
    {
        List<CryptoApiPkcs11SessionPoolMetricsSnapshot> snapshots = [];
        snapshots.AddRange(_defaultBackend.GetSessionPoolMetricsSnapshots());

        foreach (BackendRuntime backend in _namedBackends.Values.OrderBy(static backend => backend.Name, StringComparer.OrdinalIgnoreCase))
        {
            snapshots.AddRange(backend.GetSessionPoolMetricsSnapshots());
        }

        return snapshots;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        foreach (BackendRuntime backend in _namedBackends.Values)
        {
            backend.Dispose();
        }

        _namedBackends.Clear();
        _defaultBackend.Dispose();
    }

    private BackendRuntime ResolveBackend(string? deviceRoute)
    {
        ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(deviceRoute) || !HasNamedBackends)
        {
            return _defaultBackend;
        }

        string backendName = CryptoApiConfiguredRouteRegistry.NormalizeMachineName(deviceRoute, nameof(deviceRoute));
        return _namedBackends.GetOrAdd(backendName, name =>
        {
            CryptoApiRuntimeBackendOptions backendOptions = runtimeOptions.Value.Backends
                .FirstOrDefault(candidate => candidate.Enabled && string.Equals(candidate.Name, name, StringComparison.OrdinalIgnoreCase))
                ?? throw new CryptoApiOperationConfigurationException($"Crypto API backend '{name}' is not configured on this host.");

            return new BackendRuntime(new BackendConfiguration(
                Name: name,
                ModulePath: string.IsNullOrWhiteSpace(backendOptions.ModulePath) ? runtimeOptions.Value.ModulePath?.Trim() : backendOptions.ModulePath.Trim(),
                UserPin: string.IsNullOrWhiteSpace(backendOptions.UserPin) ? runtimeOptions.Value.UserPin?.Trim() : backendOptions.UserPin.Trim(),
                MaxRetainedSessionsPerSlot: Math.Max(backendOptions.MaxRetainedSessionsPerSlot ?? runtimeOptions.Value.MaxRetainedSessionsPerSlot, 0)),
                _metrics);
        });
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(CryptoApiPkcs11Runtime));
        }
    }

    private sealed record BackendConfiguration(
        string Name,
        string? ModulePath,
        string? UserPin,
        int MaxRetainedSessionsPerSlot);

    private sealed class BackendRuntime(BackendConfiguration configuration, CryptoApiMetrics? metrics) : IDisposable
    {
        private readonly object _sync = new();
        private readonly ConcurrentDictionary<Pkcs11SlotId, SlotSessionPool> _sessionPools = new();
        private readonly CryptoApiMetrics? _metrics = metrics;
        private Pkcs11Module? _module;
        private bool _disposed;

        public string Name => configuration.Name;

        public Pkcs11Module GetInitializedModule()
        {
            if (_module is not null)
            {
                return _module;
            }

            lock (_sync)
            {
                ThrowIfDisposed();

                if (_module is not null)
                {
                    return _module;
                }

                string modulePath = configuration.ModulePath?.Trim() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(modulePath))
                {
                    throw new CryptoApiOperationConfigurationException($"Crypto API PKCS#11 module path is not configured for backend '{configuration.Name}'.");
                }

                Pkcs11Module module = Pkcs11Module.Load(modulePath);
                try
                {
                    module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));
                    _module = module;
                    return module;
                }
                catch
                {
                    module.Dispose();
                    throw;
                }
            }
        }

        public CryptoApiPooledSessionLease RentSession(Pkcs11SlotId slotId)
        {
            ThrowIfDisposed();

            SlotSessionPool pool = _sessionPools.GetOrAdd(slotId, static _ => new SlotSessionPool());
            if (pool.TryRent(out Pkcs11Session? existingSession) && existingSession is not null)
            {
                _metrics?.RecordPkcs11SessionLease(configuration.Name, (ulong)slotId.Value, "reused");
                return CreateLease(slotId, existingSession);
            }

            pool.RecordNewLease();
            try
            {
                _metrics?.RecordPkcs11SessionLease(configuration.Name, (ulong)slotId.Value, "created");
                return CreateLease(slotId, CreateAuthenticatedSession(slotId));
            }
            catch
            {
                pool.AbortLease();
                throw;
            }
        }

        public IReadOnlyList<CryptoApiPkcs11SessionPoolMetricsSnapshot> GetSessionPoolMetricsSnapshots()
            => _sessionPools
                .OrderBy(static pair => pair.Key.Value)
                .Select(pair => pair.Value.CreateMetricsSnapshot(configuration.Name, (ulong)pair.Key.Value, configuration.MaxRetainedSessionsPerSlot))
                .ToArray();

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
            }

            foreach ((_, SlotSessionPool pool) in _sessionPools)
            {
                pool.Dispose();
            }

            _sessionPools.Clear();

            lock (_sync)
            {
                _module?.Dispose();
                _module = null;
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BackendRuntime));
            }
        }

        private Pkcs11Session CreateAuthenticatedSession(Pkcs11SlotId slotId)
        {
            Pkcs11Module module = GetInitializedModule();
            Pkcs11Session session = OpenCompatibleSession(module, slotId);

            try
            {
                LoginIfConfigured(session);
                return session;
            }
            catch
            {
                session.Dispose();
                throw;
            }
        }

        private void ReturnSession(Pkcs11SlotId slotId, Pkcs11Session session, bool broken)
        {
            SlotSessionPool pool = _sessionPools.GetOrAdd(slotId, static _ => new SlotSessionPool());

            if (_disposed || broken)
            {
                pool.AbortLease();
                _metrics?.RecordPkcs11SessionReturn(configuration.Name, (ulong)slotId.Value, broken ? "broken" : "disposed");
                session.Dispose();
                return;
            }

            if (!pool.TryReturn(session, configuration.MaxRetainedSessionsPerSlot))
            {
                _metrics?.RecordPkcs11SessionReturn(configuration.Name, (ulong)slotId.Value, "disposed");
                session.Dispose();
                return;
            }

            _metrics?.RecordPkcs11SessionReturn(configuration.Name, (ulong)slotId.Value, "pooled");
        }

        private CryptoApiPooledSessionLease CreateLease(Pkcs11SlotId slotId, Pkcs11Session session)
            => new(session, broken => ReturnSession(slotId, session, broken));

        private void LoginIfConfigured(Pkcs11Session session)
        {
            string userPin = configuration.UserPin?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(userPin))
            {
                return;
            }

            byte[] pinUtf8 = Encoding.UTF8.GetBytes(userPin);
            try
            {
                session.Login(Pkcs11UserType.User, pinUtf8);
            }
            catch (Pkcs11Exception ex) when ((nuint)ex.RawResult == CkrUserAlreadyLoggedIn)
            {
            }
        }

        private static Pkcs11Session OpenCompatibleSession(Pkcs11Module module, Pkcs11SlotId slotId)
        {
            try
            {
                return module.OpenSession(slotId, readWrite: false);
            }
            catch (Pkcs11Exception ex) when ((nuint)ex.RawResult == CkrFunctionFailed)
            {
                return module.OpenSession(slotId, readWrite: true);
            }
        }

    }

    internal sealed class CryptoApiPooledSessionLease(Pkcs11Session session, Action<bool> releaseAction) : IDisposable
    {
        private bool _broken;
        private bool _disposed;

        public Pkcs11Session Session { get; } = session;

        public void MarkBroken() => _broken = true;

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            releaseAction(_broken);
        }
    }

    private sealed class SlotSessionPool : IDisposable
    {
        private readonly ConcurrentQueue<Pkcs11Session> _idleSessions = new();
        private int _idleCount;
        private int _inUseCount;

        public bool TryRent(out Pkcs11Session? session)
        {
            while (_idleSessions.TryDequeue(out session))
            {
                _ = Interlocked.Decrement(ref _idleCount);
                _ = Interlocked.Increment(ref _inUseCount);
                return true;
            }

            session = null;
            return false;
        }

        public void RecordNewLease()
            => _ = Interlocked.Increment(ref _inUseCount);

        public void AbortLease()
            => _ = Interlocked.Decrement(ref _inUseCount);

        public bool TryReturn(Pkcs11Session session, int maxRetainedSessions)
        {
            _ = Interlocked.Decrement(ref _inUseCount);

            if (maxRetainedSessions <= 0)
            {
                return false;
            }

            int newIdleCount = Interlocked.Increment(ref _idleCount);
            if (newIdleCount > maxRetainedSessions)
            {
                _ = Interlocked.Decrement(ref _idleCount);
                return false;
            }

            _idleSessions.Enqueue(session);
            return true;
        }

        public CryptoApiPkcs11SessionPoolMetricsSnapshot CreateMetricsSnapshot(string backend, ulong slotId, int maxRetainedSessions)
            => new(
                Backend: backend,
                SlotId: slotId,
                IdleSessions: Math.Max(0, Volatile.Read(ref _idleCount)),
                InUseSessions: Math.Max(0, Volatile.Read(ref _inUseCount)),
                MaxRetainedSessions: Math.Max(0, maxRetainedSessions));

        public void Dispose()
        {
            while (_idleSessions.TryDequeue(out Pkcs11Session? session))
            {
                _ = Interlocked.Decrement(ref _idleCount);
                session.Dispose();
            }
        }
    }
}
