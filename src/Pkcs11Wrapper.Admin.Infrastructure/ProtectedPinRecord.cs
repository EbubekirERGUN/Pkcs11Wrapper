namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed record ProtectedPinRecord(
    Guid DeviceId,
    nuint SlotId,
    string Purpose,
    string Ciphertext,
    DateTimeOffset UpdatedUtc,
    string MaskedValue);
