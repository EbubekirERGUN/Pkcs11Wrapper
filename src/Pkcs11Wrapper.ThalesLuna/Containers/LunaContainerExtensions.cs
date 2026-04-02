namespace Pkcs11Wrapper.ThalesLuna.Containers;

public sealed class LunaContainerExtensions
{
    internal LunaContainerExtensions(bool isAvailable) => IsAvailable = isAvailable;

    public bool IsAvailable { get; }
}
