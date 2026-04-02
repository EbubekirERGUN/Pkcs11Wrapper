namespace Pkcs11Wrapper.ThalesLuna.Policy;

public sealed class LunaPolicyExtensions
{
    internal LunaPolicyExtensions(bool isAvailable) => IsAvailable = isAvailable;

    public bool IsAvailable { get; }
}
