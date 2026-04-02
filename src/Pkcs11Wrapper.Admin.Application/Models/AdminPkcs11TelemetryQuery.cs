namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record AdminPkcs11TelemetryQuery(
    int Take = 500,
    string? SearchText = null,
    string? DeviceFilter = null,
    string? SlotFilter = null,
    string? OperationFilter = null,
    string? MechanismFilter = null,
    double? MinDurationMilliseconds = null,
    string StatusFilter = "all",
    string TimeRangeFilter = "all");
