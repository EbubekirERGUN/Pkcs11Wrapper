using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Pkcs11Wrapper.Admin.Application;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Web.Configuration;

public static class TelemetryEndpoints
{
    public static async Task<IResult> ExportAsync(
        HsmAdminService admin,
        [FromQuery(Name = "take")] int? take,
        [FromQuery(Name = "search")] string? searchText,
        [FromQuery(Name = "device")] string? deviceFilter,
        [FromQuery(Name = "slot")] string? slotFilter,
        [FromQuery(Name = "operation")] string? operationFilter,
        [FromQuery(Name = "mechanism")] string? mechanismFilter,
        [FromQuery(Name = "minDurationMs")] double? minDurationMilliseconds,
        [FromQuery(Name = "status")] string? statusFilter,
        [FromQuery(Name = "timeRange")] string? timeRangeFilter,
        CancellationToken cancellationToken)
    {
        AdminPkcs11TelemetryExportBundle bundle = await admin.ExportPkcs11TelemetryAsync(
            new AdminPkcs11TelemetryQuery(
                Take: take ?? 0,
                SearchText: searchText,
                DeviceFilter: deviceFilter,
                SlotFilter: slotFilter,
                OperationFilter: operationFilter,
                MechanismFilter: mechanismFilter,
                MinDurationMilliseconds: minDurationMilliseconds,
                StatusFilter: statusFilter ?? "all",
                TimeRangeFilter: timeRangeFilter ?? "all"),
            cancellationToken);

        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(bundle, AdminApplicationJsonContext.Default.AdminPkcs11TelemetryExportBundle);
        string fileName = $"pkcs11wrapper-admin-telemetry-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json";
        return Results.File(payload, "application/json; charset=utf-8", fileName);
    }
}
