using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native;

public sealed class Pkcs11Exception : Exception
{
    public Pkcs11Exception(string operation, CK_RV result)
        : this(operation, result, Pkcs11ReturnValueTaxonomy.Classify(result))
    {
    }

    internal Pkcs11Exception(string operation, CK_RV result, Pkcs11ErrorMetadata metadata)
        : base($"PKCS#11 call '{operation}' failed with {result}.")
    {
        Operation = operation;
        Result = result;
        ErrorMetadata = metadata;
    }

    public string Operation { get; }

    public CK_RV Result { get; }

    public CK_RV RawResult => Result;

    public Pkcs11ErrorMetadata ErrorMetadata { get; }

    public Pkcs11ErrorCategory ErrorCategory => ErrorMetadata.Category;

    public bool IsRetryable => ErrorMetadata.IsRetryable;
}
