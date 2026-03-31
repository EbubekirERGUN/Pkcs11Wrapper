namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record AdminSessionSnapshot(
    Guid SessionId,
    Guid DeviceId,
    string DeviceName,
    nuint SlotId,
    bool IsReadWrite,
    string State,
    DateTimeOffset OpenedUtc,
    DateTimeOffset LastTouchedUtc,
    string LastOperation,
    bool IsHealthy,
    string? Notes);
