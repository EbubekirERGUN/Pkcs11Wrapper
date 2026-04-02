namespace Pkcs11Wrapper.ThalesLuna;

public readonly record struct LunaCapabilities(
    bool HasFunctionList,
    bool HasHighAvailability,
    bool HasCloning,
    bool HasPolicy,
    bool HasPedMofn,
    bool HasContainers,
    bool HasKeys);
