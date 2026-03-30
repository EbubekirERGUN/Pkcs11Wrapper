using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native;

public enum Pkcs11ErrorCategory
{
    Unknown = 0,
    Success = 1,
    Lifecycle = 2,
    StateConflict = 3,
    InputValidation = 4,
    Authentication = 5,
    ObjectHandle = 6,
    Capability = 7,
    Resource = 8,
    Device = 9,
    Session = 10,
    Integrity = 11,
}

public readonly record struct Pkcs11ErrorMetadata(Pkcs11ErrorCategory Category, bool IsRetryable)
{
    public static readonly Pkcs11ErrorMetadata Unknown = new(Pkcs11ErrorCategory.Unknown, false);
}

public static class Pkcs11ReturnValueTaxonomy
{
    private static readonly IReadOnlyDictionary<nuint, Pkcs11ErrorMetadata> MetadataByReturnValue = new Dictionary<nuint, Pkcs11ErrorMetadata>
    {
        [CK_RV.Ok.Value] = new(Pkcs11ErrorCategory.Success, false),

        [Pkcs11ReturnValues.CryptokiNotInitialized.Value] = new(Pkcs11ErrorCategory.Lifecycle, true),
        [Pkcs11ReturnValues.CryptokiAlreadyInitialized.Value] = new(Pkcs11ErrorCategory.StateConflict, false),
        [Pkcs11ReturnValues.OperationActive.Value] = new(Pkcs11ErrorCategory.StateConflict, true),
        [Pkcs11ReturnValues.OperationNotInitialized.Value] = new(Pkcs11ErrorCategory.Lifecycle, true),

        [Pkcs11ReturnValues.ArgumentsBad.Value] = new(Pkcs11ErrorCategory.InputValidation, false),
        [Pkcs11ReturnValues.AttributeTypeInvalid.Value] = new(Pkcs11ErrorCategory.InputValidation, false),
        [Pkcs11ReturnValues.TemplateIncomplete.Value] = new(Pkcs11ErrorCategory.InputValidation, false),
        [Pkcs11ReturnValues.TemplateInconsistent.Value] = new(Pkcs11ErrorCategory.InputValidation, false),
        [Pkcs11ReturnValues.BufferTooSmall.Value] = new(Pkcs11ErrorCategory.InputValidation, true),
        [Pkcs11ReturnValues.MechanismParamInvalid.Value] = new(Pkcs11ErrorCategory.InputValidation, false),

        [Pkcs11ReturnValues.PinIncorrect.Value] = new(Pkcs11ErrorCategory.Authentication, false),
        [Pkcs11ReturnValues.UserNotLoggedIn.Value] = new(Pkcs11ErrorCategory.Authentication, true),
        [Pkcs11ReturnValues.UserAlreadyLoggedIn.Value] = new(Pkcs11ErrorCategory.Authentication, false),

        [Pkcs11ReturnValues.ObjectHandleInvalid.Value] = new(Pkcs11ErrorCategory.ObjectHandle, false),
        [Pkcs11ReturnValues.KeyHandleInvalid.Value] = new(Pkcs11ErrorCategory.ObjectHandle, false),
        [Pkcs11ReturnValues.SessionHandleInvalid.Value] = new(Pkcs11ErrorCategory.ObjectHandle, false),

        [Pkcs11ReturnValues.FunctionNotSupported.Value] = new(Pkcs11ErrorCategory.Capability, false),
        [Pkcs11ReturnValues.FunctionNotParallel.Value] = new(Pkcs11ErrorCategory.Capability, false),
        [Pkcs11ReturnValues.MechanismInvalid.Value] = new(Pkcs11ErrorCategory.Capability, false),
        [Pkcs11ReturnValues.KeyTypeInconsistent.Value] = new(Pkcs11ErrorCategory.Capability, false),
        [Pkcs11ReturnValues.KeyUnwrappable.Value] = new(Pkcs11ErrorCategory.Capability, false),
        [Pkcs11ReturnValues.KeyFunctionNotPermitted.Value] = new(Pkcs11ErrorCategory.Capability, false),

        [Pkcs11ReturnValues.HostMemory.Value] = new(Pkcs11ErrorCategory.Resource, true),
        [Pkcs11ReturnValues.DeviceMemory.Value] = new(Pkcs11ErrorCategory.Resource, true),
        [Pkcs11ReturnValues.SessionCount.Value] = new(Pkcs11ErrorCategory.Resource, true),

        [Pkcs11ReturnValues.DeviceError.Value] = new(Pkcs11ErrorCategory.Device, true),
        [Pkcs11ReturnValues.DeviceRemoved.Value] = new(Pkcs11ErrorCategory.Device, true),
        [Pkcs11ReturnValues.TokenNotPresent.Value] = new(Pkcs11ErrorCategory.Device, true),
        [Pkcs11ReturnValues.TokenNotRecognized.Value] = new(Pkcs11ErrorCategory.Device, false),
        [Pkcs11ReturnValues.TokenWriteProtected.Value] = new(Pkcs11ErrorCategory.Device, false),

        [Pkcs11ReturnValues.SessionClosed.Value] = new(Pkcs11ErrorCategory.Session, true),
        [Pkcs11ReturnValues.SessionReadOnly.Value] = new(Pkcs11ErrorCategory.Session, false),
        [Pkcs11ReturnValues.SessionReadOnlyExists.Value] = new(Pkcs11ErrorCategory.Session, false),

        [Pkcs11ReturnValues.SignatureInvalid.Value] = new(Pkcs11ErrorCategory.Integrity, false),
        [Pkcs11ReturnValues.SignatureLenRange.Value] = new(Pkcs11ErrorCategory.Integrity, false),
        [Pkcs11ReturnValues.AttributeSensitive.Value] = new(Pkcs11ErrorCategory.Integrity, false),
        [Pkcs11ReturnValues.KeyUnextractable.Value] = new(Pkcs11ErrorCategory.Integrity, false),
    };

    public static Pkcs11ErrorMetadata Classify(CK_RV result)
    {
        if (MetadataByReturnValue.TryGetValue(result.Value, out Pkcs11ErrorMetadata metadata))
        {
            return metadata;
        }

        return Pkcs11ErrorMetadata.Unknown;
    }
}
