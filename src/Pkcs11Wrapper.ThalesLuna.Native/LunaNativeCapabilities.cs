namespace Pkcs11Wrapper.ThalesLuna.Native;

public readonly record struct LunaNativeCapabilities(
    bool HasFunctionList,
    bool HasHighAvailability,
    bool HasCloning,
    bool HasPolicy,
    bool HasPedMofn,
    bool HasContainers,
    bool HasKeys);
