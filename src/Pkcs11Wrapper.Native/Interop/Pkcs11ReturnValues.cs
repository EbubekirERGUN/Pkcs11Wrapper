namespace Pkcs11Wrapper.Native.Interop;

internal static class Pkcs11ReturnValues
{
    public static readonly CK_RV ArgumentsBad = new(0x00000007u);
    public static readonly CK_RV AttributeSensitive = new(0x00000011u);
    public static readonly CK_RV AttributeTypeInvalid = new(0x00000012u);
    public static readonly CK_RV BufferTooSmall = new(0x00000150u);
    public static readonly CK_RV CryptokiAlreadyInitialized = new(0x00000191u);
    public static readonly CK_RV CryptokiNotInitialized = new(0x00000190u);
    public static readonly CK_RV DeviceError = new(0x00000030u);
    public static readonly CK_RV DeviceMemory = new(0x00000031u);
    public static readonly CK_RV DeviceRemoved = new(0x00000032u);
    public static readonly CK_RV FunctionFailed = new(0x00000006u);
    public static readonly CK_RV FunctionNotParallel = new(0x00000051u);
    public static readonly CK_RV FunctionNotSupported = new(0x00000054u);
    public static readonly CK_RV GeneralError = new(0x00000005u);
    public static readonly CK_RV HostMemory = new(0x00000002u);
    public static readonly CK_RV KeyFunctionNotPermitted = new(0x00000068u);
    public static readonly CK_RV KeyHandleInvalid = new(0x00000060u);
    public static readonly CK_RV KeyTypeInconsistent = new(0x00000063u);
    public static readonly CK_RV KeyUnextractable = new(0x0000006au);
    public static readonly CK_RV KeyUnwrappable = new(0x00000067u);
    public static readonly CK_RV MechanismInvalid = new(0x00000070u);
    public static readonly CK_RV MechanismParamInvalid = new(0x00000071u);
    public static readonly CK_RV ObjectHandleInvalid = new(0x00000082u);
    public static readonly CK_RV OperationActive = new(0x00000090u);
    public static readonly CK_RV OperationNotInitialized = new(0x00000091u);
    public static readonly CK_RV NoEvent = new(0x00000008u);
    public static readonly CK_RV PinIncorrect = new(0x000000a0u);
    public static readonly CK_RV TemplateIncomplete = new(0x000000d0u);
    public static readonly CK_RV TemplateInconsistent = new(0x000000d1u);
    public static readonly CK_RV TokenNotPresent = new(0x000000e0u);
    public static readonly CK_RV TokenNotRecognized = new(0x000000e1u);
    public static readonly CK_RV TokenWriteProtected = new(0x000000e2u);
    public static readonly CK_RV UserAlreadyLoggedIn = new(0x00000100u);
    public static readonly CK_RV UserNotLoggedIn = new(0x00000101u);
    public static readonly CK_RV SessionClosed = new(0x000000b0u);
    public static readonly CK_RV SessionHandleInvalid = new(0x000000b3u);
    public static readonly CK_RV SessionCount = new(0x000000b1u);
    public static readonly CK_RV SessionReadOnly = new(0x000000b5u);
    public static readonly CK_RV SessionReadOnlyExists = new(0x000000b7u);
    public static readonly CK_RV SignatureInvalid = new(0x000000c0u);
    public static readonly CK_RV SignatureLenRange = new(0x000000c1u);
}
