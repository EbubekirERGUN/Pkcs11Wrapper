using System.Runtime.InteropServices;
using Pkcs11Wrapper.Native.Interop;
using Pkcs11Wrapper.ThalesLuna.Native.Interop;

namespace Pkcs11Wrapper.ThalesLuna.Tests;

public sealed class LunaNativeTypeLayoutTests
{
    [Fact]
    public void LunaFunctionListHeaderMatchesVersionLayout()
    {
        Assert.Equal(Marshal.SizeOf<CK_VERSION>(), Marshal.SizeOf<LunaFunctionListHeader>());
    }
}
