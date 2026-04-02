using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;
using Pkcs11Wrapper.ThalesLuna.Native.Interop;

namespace Pkcs11Wrapper.ThalesLuna.Native;

public sealed unsafe class LunaNativeModule : IDisposable
{
    private readonly CK_VERSION _functionListVersion;
    private bool _disposed;

    private LunaNativeModule(CK_VERSION functionListVersion, LunaNativeCapabilities capabilities)
    {
        _functionListVersion = functionListVersion;
        Capabilities = capabilities;
    }

    public CK_VERSION FunctionListVersion
    {
        get
        {
            EnsureNotDisposed();
            return _functionListVersion;
        }
    }

    public LunaNativeCapabilities Capabilities { get; }

    public bool IsAvailable => Capabilities.HasFunctionList;

    public static bool TryLoad(Pkcs11NativeModule module, out LunaNativeModule? lunaModule)
    {
        ArgumentNullException.ThrowIfNull(module);

        if (!module.TryResolveOptionalExport("CA_GetFunctionList", out nint exportAddress))
        {
            lunaModule = null;
            return false;
        }

        delegate* unmanaged[Cdecl]<LunaFunctionListHeader**, CK_RV> getFunctionList = (delegate* unmanaged[Cdecl]<LunaFunctionListHeader**, CK_RV>)exportAddress;

        LunaFunctionListHeader* functionList = null;
        CK_RV result = getFunctionList(&functionList);
        if (result == Pkcs11ReturnValues.FunctionNotSupported)
        {
            lunaModule = null;
            return false;
        }

        Pkcs11NativeModule.ThrowIfFailed(result, "CA_GetFunctionList");

        if (functionList is null)
        {
            throw new InvalidOperationException("CA_GetFunctionList succeeded but returned a null Luna extension function table.");
        }

        lunaModule = new LunaNativeModule(
            functionList->Version,
            new LunaNativeCapabilities(
                HasFunctionList: true,
                HasHighAvailability: false,
                HasCloning: false,
                HasPolicy: false,
                HasPedMofn: false,
                HasContainers: false,
                HasKeys: false));

        return true;
    }

    public void Dispose() => _disposed = true;

    private void EnsureNotDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(LunaNativeModule));
        }
    }
}
