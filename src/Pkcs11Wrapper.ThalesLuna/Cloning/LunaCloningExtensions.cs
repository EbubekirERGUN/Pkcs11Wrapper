namespace Pkcs11Wrapper.ThalesLuna.Cloning;

public sealed class LunaCloningExtensions
{
    internal LunaCloningExtensions(bool isAvailable) => IsAvailable = isAvailable;

    public bool IsAvailable { get; }
}
