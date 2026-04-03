namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record HsmSlotSummary(
    Guid DeviceId,
    nuint SlotId,
    string SlotDescription,
    string SlotManufacturer,
    string SlotFlags,
    bool TokenPresent,
    bool TokenInitialized,
    string? TokenLabel,
    string? TokenModel,
    string? TokenSerialNumber,
    string? TokenFlags,
    int MechanismCount)
{
    public bool CanOpenSessions => TokenPresent && TokenInitialized;

    public bool RequiresInitialization => TokenPresent && !TokenInitialized;

    public string SessionOpenUnavailableReason => !TokenPresent
        ? "No token is present in this slot, so session-based actions are unavailable."
        : TokenInitialized
            ? string.Empty
            : "The slot reports token info, but the token is not initialized yet. Session-based actions stay disabled until initialization completes.";
}
