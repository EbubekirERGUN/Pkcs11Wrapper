using Microsoft.Extensions.Options;
using Pkcs11Wrapper;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Operations;

namespace Pkcs11Wrapper.CryptoApi.Runtime;

public sealed class CryptoApiPkcs11Runtime(IOptions<CryptoApiRuntimeOptions> runtimeOptions) : IDisposable
{
    private readonly object _sync = new();
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
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(CryptoApiPkcs11Runtime));
            }

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

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _module?.Dispose();
            _module = null;
        }
    }
}
