namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record HsmConnectionTestResult(
    bool Success,
    string Message,
    int SlotCount,
    bool SupportsInterfaceDiscovery,
    string? LibraryDescription,
    string? ManufacturerId,
    string? ErrorCode = null);
