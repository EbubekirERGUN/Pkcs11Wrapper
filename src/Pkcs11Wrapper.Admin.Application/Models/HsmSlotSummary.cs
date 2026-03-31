namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record HsmSlotSummary(
    Guid DeviceId,
    nuint SlotId,
    string SlotDescription,
    string SlotManufacturer,
    string SlotFlags,
    bool TokenPresent,
    string? TokenLabel,
    string? TokenModel,
    string? TokenSerialNumber,
    string? TokenFlags,
    int MechanismCount);
