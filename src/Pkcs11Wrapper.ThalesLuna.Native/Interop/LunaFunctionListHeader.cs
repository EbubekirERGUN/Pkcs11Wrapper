using System.Runtime.InteropServices;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.ThalesLuna.Native.Interop;

[StructLayout(LayoutKind.Sequential)]
public readonly struct LunaFunctionListHeader
{
    public LunaFunctionListHeader(CK_VERSION version) => Version = version;

    public readonly CK_VERSION Version;
}
