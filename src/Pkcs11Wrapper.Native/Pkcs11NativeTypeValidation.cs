using System.Runtime.CompilerServices;

namespace Pkcs11Wrapper.Native;

public static class Pkcs11NativeTypeValidation
{
    public static bool IsBlittable<T>()
        where T : unmanaged
        => !RuntimeHelpers.IsReferenceOrContainsReferences<T>();
}
