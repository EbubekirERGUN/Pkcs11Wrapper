namespace Pkcs11Wrapper.ThalesLuna.Keys;

public sealed class LunaKeyExtensions
{
    internal LunaKeyExtensions(bool isAvailable) => IsAvailable = isAvailable;

    public bool IsAvailable { get; }
}
