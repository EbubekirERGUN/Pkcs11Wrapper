namespace Pkcs11Wrapper.Admin.Application.Models;

public enum Pkcs11LabOperation
{
    ModuleInfo = 0,
    InterfaceDiscovery = 1,
    SlotSnapshot = 2,
    MechanismList = 3,
    MechanismInfo = 4,
    SessionInfo = 5,
    GenerateRandom = 6,
    DigestText = 7,
    FindObjects = 8,
    SignData = 9,
    VerifySignature = 10,
    EncryptData = 11,
    DecryptData = 12,
    InspectObject = 13,
    WrapKey = 14,
    UnwrapAesKey = 15,
    ReadAttribute = 16
}

public enum Pkcs11LabDigestAlgorithm
{
    Sha1 = 0,
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3
}

public enum Pkcs11LabObjectClassFilter
{
    Any = 0,
    Data = 1,
    Certificate = 2,
    PublicKey = 3,
    PrivateKey = 4,
    SecretKey = 5
}

public enum Pkcs11LabPayloadEncoding
{
    Utf8Text = 0,
    Hex = 1
}

public sealed class Pkcs11LabRequest
{
    public Guid DeviceId { get; set; }

    public nuint? SlotId { get; set; }

    public Pkcs11LabOperation Operation { get; set; } = Pkcs11LabOperation.ModuleInfo;

    public bool OpenReadWriteSession { get; set; }

    public bool LoginUserIfPinProvided { get; set; } = true;

    public string? UserPin { get; set; }

    public string? MechanismTypeText { get; set; }

    public string? AttributeTypeText { get; set; }

    public string? KeyHandleText { get; set; }

    public string? SecondaryKeyHandleText { get; set; }

    public Pkcs11LabDigestAlgorithm DigestAlgorithm { get; set; } = Pkcs11LabDigestAlgorithm.Sha256;

    public Pkcs11LabPayloadEncoding PayloadEncoding { get; set; } = Pkcs11LabPayloadEncoding.Utf8Text;

    public string? TextInput { get; set; }

    public string? DataHex { get; set; }

    public string? SignatureHex { get; set; }

    public string? UnwrapTargetLabel { get; set; }

    public string? UnwrapTargetIdHex { get; set; }

    public bool UnwrapTokenObject { get; set; }

    public bool UnwrapPrivateObject { get; set; } = true;

    public bool UnwrapSensitive { get; set; } = true;

    public bool UnwrapExtractable { get; set; }

    public bool UnwrapAllowEncrypt { get; set; } = true;

    public bool UnwrapAllowDecrypt { get; set; } = true;

    public string? LabelFilter { get; set; }

    public string? IdHex { get; set; }

    public Pkcs11LabObjectClassFilter ObjectClassFilter { get; set; } = Pkcs11LabObjectClassFilter.Any;

    public int RandomLength { get; set; } = 32;

    public int MaxObjects { get; set; } = 20;
}

public sealed record Pkcs11LabExecutionResult(
    string Operation,
    bool Success,
    string Summary,
    string OutputText,
    IReadOnlyList<string> Notes,
    long DurationMilliseconds);
