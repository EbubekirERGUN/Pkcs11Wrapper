namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record AdminPkcs11TelemetryField(
    string Name,
    string Classification,
    string? Value);

public sealed record AdminPkcs11TelemetryEntry(
    Guid Id,
    DateTimeOffset TimestampUtc,
    Guid DeviceId,
    string DeviceName,
    string OperationName,
    string? NativeOperationName,
    string Status,
    double DurationMilliseconds,
    string? ReturnValue,
    ulong? SlotId,
    ulong? SessionHandle,
    ulong? MechanismType,
    string? ExceptionType,
    AdminPkcs11TelemetryField[] Fields);
