namespace Pkcs11Wrapper.ThalesLuna.HighAvailability;

public sealed class LunaHighAvailabilityExtensions
{
    internal LunaHighAvailabilityExtensions(bool isAvailable) => IsAvailable = isAvailable;

    public bool IsAvailable { get; }
}
