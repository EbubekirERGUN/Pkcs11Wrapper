using System.Collections.Concurrent;
using System.Threading;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class AdminPkcs11Runtime : IDisposable
{
    private readonly ConcurrentDictionary<string, SharedModuleOwner> _owners = new(StringComparer.Ordinal);
    private int _disposed;

    public AdminPkcs11ModuleLease Acquire(HsmDeviceProfile device, IPkcs11OperationTelemetryListener? telemetryListener = null)
    {
        ArgumentNullException.ThrowIfNull(device);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        string modulePath = NormalizeModulePath(device.ModulePath);
        SharedModuleOwner owner = _owners.GetOrAdd(modulePath, static path => new SharedModuleOwner(path));
        owner.AcquireReference();

        Pkcs11Module module = Pkcs11Module.Load(modulePath, telemetryListener);
        try
        {
            module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));
            return new AdminPkcs11ModuleLease(module, owner.ReleaseReference);
        }
        catch
        {
            module.Dispose();
            owner.ReleaseReference();
            throw;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (SharedModuleOwner owner in _owners.Values)
        {
            owner.Dispose();
        }

        _owners.Clear();
    }

    private static string NormalizeModulePath(string? modulePath)
        => string.IsNullOrWhiteSpace(modulePath)
            ? throw new ArgumentException("PKCS#11 module path is required.", nameof(modulePath))
            : modulePath.Trim();

    private sealed class SharedModuleOwner(string modulePath) : IDisposable
    {
        private readonly object _sync = new();
        private Pkcs11Module? _ownerModule;
        private int _leaseCount;
        private bool _disposed;

        public void AcquireReference()
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                _ownerModule ??= CreateOwnerModule(modulePath);
                _leaseCount++;
            }
        }

        public void ReleaseReference()
        {
            Pkcs11Module? ownerToDispose = null;
            lock (_sync)
            {
                if (_leaseCount > 0)
                {
                    _leaseCount--;
                }

                if (_disposed && _leaseCount == 0)
                {
                    ownerToDispose = _ownerModule;
                    _ownerModule = null;
                }
            }

            ownerToDispose?.Dispose();
        }

        public void Dispose()
        {
            Pkcs11Module? ownerToDispose = null;
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                if (_leaseCount == 0)
                {
                    ownerToDispose = _ownerModule;
                    _ownerModule = null;
                }
            }

            ownerToDispose?.Dispose();
        }

        private static Pkcs11Module CreateOwnerModule(string modulePath)
        {
            Pkcs11Module owner = Pkcs11Module.Load(modulePath);
            try
            {
                owner.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));
                return owner;
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(SharedModuleOwner));
            }
        }
    }
}

public sealed class AdminPkcs11ModuleLease(Pkcs11Module module, Action releaseAction) : IDisposable
{
    private readonly Action _releaseAction = releaseAction ?? throw new ArgumentNullException(nameof(releaseAction));
    private int _disposed;

    public Pkcs11Module Module { get; } = module ?? throw new ArgumentNullException(nameof(module));

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            Module.Dispose();
        }
        finally
        {
            _releaseAction();
        }
    }
}
