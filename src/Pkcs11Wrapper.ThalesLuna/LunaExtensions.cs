using Pkcs11Wrapper;
using Pkcs11Wrapper.Native.Interop;
using Pkcs11Wrapper.ThalesLuna.Cloning;
using Pkcs11Wrapper.ThalesLuna.Containers;
using Pkcs11Wrapper.ThalesLuna.HighAvailability;
using Pkcs11Wrapper.ThalesLuna.Keys;
using Pkcs11Wrapper.ThalesLuna.Native;
using Pkcs11Wrapper.ThalesLuna.PedMofn;
using Pkcs11Wrapper.ThalesLuna.Policy;

namespace Pkcs11Wrapper.ThalesLuna;

public sealed class LunaExtensions : IDisposable
{
    private readonly LunaNativeModule _nativeModule;

    private LunaExtensions(LunaNativeModule nativeModule)
    {
        _nativeModule = nativeModule;
        FunctionListVersion = nativeModule.FunctionListVersion;

        LunaNativeCapabilities nativeCapabilities = nativeModule.Capabilities;
        Capabilities = new LunaCapabilities(
            nativeCapabilities.HasFunctionList,
            nativeCapabilities.HasHighAvailability,
            nativeCapabilities.HasCloning,
            nativeCapabilities.HasPolicy,
            nativeCapabilities.HasPedMofn,
            nativeCapabilities.HasContainers,
            nativeCapabilities.HasKeys);

        HighAvailability = new LunaHighAvailabilityExtensions(Capabilities.HasHighAvailability);
        Cloning = new LunaCloningExtensions(Capabilities.HasCloning);
        Policy = new LunaPolicyExtensions(Capabilities.HasPolicy);
        PedMofn = new LunaPedMofnExtensions(Capabilities.HasPedMofn);
        Containers = new LunaContainerExtensions(Capabilities.HasContainers);
        Keys = new LunaKeyExtensions(Capabilities.HasKeys);
    }

    public CK_VERSION FunctionListVersion { get; }

    public LunaCapabilities Capabilities { get; }

    public bool IsAvailable => Capabilities.HasFunctionList;

    public LunaHighAvailabilityExtensions HighAvailability { get; }

    public LunaCloningExtensions Cloning { get; }

    public LunaPolicyExtensions Policy { get; }

    public LunaPedMofnExtensions PedMofn { get; }

    public LunaContainerExtensions Containers { get; }

    public LunaKeyExtensions Keys { get; }

    public static bool TryLoad(Pkcs11Module module, out LunaExtensions? luna)
    {
        ArgumentNullException.ThrowIfNull(module);

        if (!LunaNativeModule.TryLoad(module.NativeModule, out LunaNativeModule? nativeModule))
        {
            luna = null;
            return false;
        }

        luna = new LunaExtensions(nativeModule!);
        return true;
    }

    public void Dispose() => _nativeModule.Dispose();
}
