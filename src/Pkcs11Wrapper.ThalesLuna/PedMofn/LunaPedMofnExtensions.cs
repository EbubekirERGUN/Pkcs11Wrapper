namespace Pkcs11Wrapper.ThalesLuna.PedMofn;

public sealed class LunaPedMofnExtensions
{
    internal LunaPedMofnExtensions(bool isAvailable) => IsAvailable = isAvailable;

    public bool IsAvailable { get; }
}
