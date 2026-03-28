using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native;

public sealed class Pkcs11Exception : Exception
{
    public Pkcs11Exception(string operation, CK_RV result)
        : base($"PKCS#11 call '{operation}' failed with {result}.")
    {
        Operation = operation;
        Result = result;
    }

    public string Operation { get; }

    public CK_RV Result { get; }
}
