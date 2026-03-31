namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record HsmObjectAttributeView(string Name, string Value, bool IsSensitive = false);

public sealed record HsmObjectDetail(
    Guid DeviceId,
    nuint SlotId,
    nuint Handle,
    string? Label,
    string? IdHex,
    string ObjectClass,
    string KeyType,
    bool? Token,
    bool? Private,
    bool? Modifiable,
    bool? Sensitive,
    bool? Extractable,
    bool? CanEncrypt,
    bool? CanDecrypt,
    bool? CanSign,
    bool? CanVerify,
    bool? CanWrap,
    bool? CanUnwrap,
    bool? CanDerive,
    nuint? SizeBytes,
    nuint? ValueLength,
    nuint? ModulusBits,
    string? PublicExponentHex,
    string? EcParametersHex,
    IReadOnlyList<HsmObjectAttributeView> Attributes);
