namespace Pkcs11Wrapper.Native.Interop;

internal static class Pkcs11ReturnValues
{
    public static readonly CK_RV AttributeSensitive = new(0x00000011u);
    public static readonly CK_RV AttributeTypeInvalid = new(0x00000012u);
    public static readonly CK_RV BufferTooSmall = new(0x00000150u);
    public static readonly CK_RV CryptokiAlreadyInitialized = new(0x00000191u);
    public static readonly CK_RV CryptokiNotInitialized = new(0x00000190u);
    public static readonly CK_RV ObjectHandleInvalid = new(0x00000082u);
    public static readonly CK_RV OperationActive = new(0x00000090u);
    public static readonly CK_RV OperationNotInitialized = new(0x00000091u);
    public static readonly CK_RV TemplateIncomplete = new(0x000000d0u);
    public static readonly CK_RV TemplateInconsistent = new(0x000000d1u);
    public static readonly CK_RV TokenNotPresent = new(0x000000e0u);
    public static readonly CK_RV UserNotLoggedIn = new(0x00000101u);
    public static readonly CK_RV SignatureInvalid = new(0x000000c0u);
    public static readonly CK_RV SignatureLenRange = new(0x000000c1u);
}
