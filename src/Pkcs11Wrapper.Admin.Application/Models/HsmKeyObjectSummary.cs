namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record HsmKeyObjectSummary(
    Guid DeviceId,
    nuint SlotId,
    nuint Handle,
    string? Label,
    string? IdHex,
    string ObjectClass,
    string KeyType,
    bool? CanEncrypt,
    bool? CanDecrypt,
    bool? CanSign,
    bool? CanVerify,
    bool? CanWrap,
    bool? CanUnwrap);
