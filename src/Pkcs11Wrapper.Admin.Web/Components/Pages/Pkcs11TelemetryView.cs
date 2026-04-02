using Microsoft.AspNetCore.WebUtilities;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Web.Components.Pages;

public static class Pkcs11TelemetryView
{
    public static IReadOnlyList<AdminPkcs11TelemetryEntry> Apply(
        IReadOnlyList<AdminPkcs11TelemetryEntry> items,
        string? searchText,
        string? deviceFilter,
        string? slotFilter,
        string? operationFilter,
        string? mechanismFilter,
        string statusFilter,
        string timeRangeFilter,
        DateTimeOffset nowUtc)
        => Pkcs11TelemetryQueryEvaluator.Apply(
            items,
            new AdminPkcs11TelemetryQuery(
                SearchText: searchText,
                DeviceFilter: deviceFilter,
                SlotFilter: slotFilter,
                OperationFilter: operationFilter,
                MechanismFilter: mechanismFilter,
                StatusFilter: statusFilter,
                TimeRangeFilter: timeRangeFilter),
            nowUtc);

    public static bool IsSuccess(AdminPkcs11TelemetryEntry item)
        => Pkcs11TelemetryQueryEvaluator.IsSuccess(item);

    public static string GetStatusBadgeClass(AdminPkcs11TelemetryEntry item)
        => item.Status switch
        {
            "Succeeded" => "text-bg-success",
            "ReturnedFalse" => "text-bg-warning",
            _ => "text-bg-danger"
        };

    public static string FormatMechanism(ulong? value)
        => Pkcs11TelemetryQueryEvaluator.FormatMechanism(value);

    public static string FormatDecimal(ulong? value)
        => Pkcs11TelemetryQueryEvaluator.FormatDecimal(value);

    public static string BuildAuditHref(AdminPkcs11TelemetryEntry item)
    {
        string? search = !string.IsNullOrWhiteSpace(item.SessionId)
            ? item.SessionId
            : !string.IsNullOrWhiteSpace(item.CorrelationId)
                ? item.CorrelationId
                : item.Actor;

        return string.IsNullOrWhiteSpace(search)
            ? "/audit"
            : QueryHelpers.AddQueryString("/audit", "q", search);
    }
}
