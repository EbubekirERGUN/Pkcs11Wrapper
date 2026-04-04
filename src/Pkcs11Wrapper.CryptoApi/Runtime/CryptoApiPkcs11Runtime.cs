using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Operations;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.CryptoApi.Runtime;

public sealed class CryptoApiPkcs11Runtime(IOptions<CryptoApiRuntimeOptions> runtimeOptions) : IDisposable
{
    private static readonly nuint CkrFunctionFailed = 0x00000006u;
    private static readonly nuint CkrUserAlreadyLoggedIn = 0x00000100u;
    private readonly object _sync = new();
    private readonly ConcurrentDictionary<Pkcs11SlotId, SlotSessionPool> _sessionPools = new();
    private Pkcs11Module? _module;
    private bool _disposed;

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

            string modulePath = runtimeOptions.Value.ModulePath?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(modulePath))
            {
                throw new CryptoApiOperationConfigurationException("Crypto API PKCS#11 module path is not configured.");
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

    internal CryptoApiPooledSessionLease RentSession(Pkcs11SlotId slotId)
    {
        ThrowIfDisposed();

        SlotSessionPool pool = _sessionPools.GetOrAdd(slotId, static _ => new SlotSessionPool());
        if (pool.TryRent(out Pkcs11Session? existingSession) && existingSession is not null)
        {
            return new CryptoApiPooledSessionLease(this, slotId, existingSession);
        }

        return new CryptoApiPooledSessionLease(this, slotId, CreateAuthenticatedSession(slotId));
    }

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
            throw new ObjectDisposedException(nameof(CryptoApiPkcs11Runtime));
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
        if (_disposed || broken)
        {
            session.Dispose();
            return;
        }

        SlotSessionPool pool = _sessionPools.GetOrAdd(slotId, static _ => new SlotSessionPool());
        if (!pool.TryReturn(session, GetMaxRetainedSessionsPerSlot()))
        {
            session.Dispose();
        }
    }

    private int GetMaxRetainedSessionsPerSlot()
        => Math.Max(runtimeOptions.Value.MaxRetainedSessionsPerSlot, 0);

    private void LoginIfConfigured(Pkcs11Session session)
    {
        string userPin = runtimeOptions.Value.UserPin?.Trim() ?? string.Empty;
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

    internal sealed class CryptoApiPooledSessionLease : IDisposable
    {
        private readonly CryptoApiPkcs11Runtime _runtime;
        private readonly Pkcs11SlotId _slotId;
        private bool _broken;
        private bool _disposed;

        public CryptoApiPooledSessionLease(CryptoApiPkcs11Runtime runtime, Pkcs11SlotId slotId, Pkcs11Session session)
        {
            _runtime = runtime;
            _slotId = slotId;
            Session = session;
        }

        public Pkcs11Session Session { get; }

        public void MarkBroken() => _broken = true;

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _runtime.ReturnSession(_slotId, Session, _broken);
        }
    }

    private sealed class SlotSessionPool : IDisposable
    {
        private readonly ConcurrentQueue<Pkcs11Session> _idleSessions = new();
        private int _idleCount;

        public bool TryRent(out Pkcs11Session? session)
        {
            while (_idleSessions.TryDequeue(out session))
            {
                _ = Interlocked.Decrement(ref _idleCount);
                return true;
            }

            session = null;
            return false;
        }

        public bool TryReturn(Pkcs11Session session, int maxRetainedSessions)
        {
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
