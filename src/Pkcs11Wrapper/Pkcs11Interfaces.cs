using System.Runtime.InteropServices;
using System.Text;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper;

public readonly record struct Pkcs11Interface(string Name, CK_VERSION Version, Pkcs11InterfaceFlags Flags)
{
    internal static unsafe Pkcs11Interface FromNative(CK_INTERFACE nativeInterface)
    {
        string name = nativeInterface.InterfaceName is null
            ? string.Empty
            : Marshal.PtrToStringUTF8((nint)nativeInterface.InterfaceName) ?? string.Empty;

        CK_VERSION version = nativeInterface.FunctionList is null
            ? default
            : ((CK_FUNCTION_LIST*)nativeInterface.FunctionList)->Version;

        return new Pkcs11Interface(name, version, (Pkcs11InterfaceFlags)(ulong)nativeInterface.Flags.Value);
    }

    public byte[] GetNameUtf8() => Encoding.UTF8.GetBytes(Name);
}

[Flags]
public enum Pkcs11InterfaceFlags : ulong
{
    None = 0,
    ForkSafe = 0x00000001
}

[Flags]
public enum Pkcs11MessageFlags : ulong
{
    None = 0,
    EndOfMessage = 0x00000001
}
