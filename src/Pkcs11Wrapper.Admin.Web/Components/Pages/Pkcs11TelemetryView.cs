using System.Globalization;
using Pkcs11Wrapper.Admin.Application.Models;

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
    {
        IEnumerable<AdminPkcs11TelemetryEntry> query = items;

        if (!string.IsNullOrWhiteSpace(searchText))
        {
            string term = searchText.Trim();
            query = query.Where(item =>
                Contains(item.DeviceName, term)
                || Contains(item.OperationName, term)
                || Contains(item.NativeOperationName, term)
                || Contains(item.Status, term)
                || Contains(item.ReturnValue, term)
                || Contains(item.ExceptionType, term)
                || Contains(FormatDecimal(item.SlotId), term)
                || Contains(FormatDecimal(item.SessionHandle), term)
                || Contains(FormatMechanism(item.MechanismType), term)
                || item.Fields.Any(field =>
                    Contains(field.Name, term)
                    || Contains(field.Classification, term)
                    || Contains(field.Value, term)));
        }

        if (!string.IsNullOrWhiteSpace(deviceFilter))
        {
            query = query.Where(item => string.Equals(item.DeviceName, deviceFilter, StringComparison.Ordinal));
        }

        if (!string.IsNullOrWhiteSpace(slotFilter))
        {
            string slotTerm = slotFilter.Trim();
            query = query.Where(item => MatchesNumericFilter(item.SlotId, slotTerm));
        }

        if (!string.IsNullOrWhiteSpace(operationFilter))
        {
            query = query.Where(item => string.Equals(item.OperationName, operationFilter, StringComparison.Ordinal));
        }

        if (!string.IsNullOrWhiteSpace(mechanismFilter))
        {
            string mechanismTerm = mechanismFilter.Trim();
            query = query.Where(item => MatchesNumericFilter(item.MechanismType, mechanismTerm));
        }

        query = statusFilter.ToLowerInvariant() switch
        {
            "success" => query.Where(IsSuccess),
            "non-success" => query.Where(item => !IsSuccess(item)),
            "returned-false" => query.Where(item => string.Equals(item.Status, "ReturnedFalse", StringComparison.Ordinal)),
            "failed" => query.Where(item => string.Equals(item.Status, "Failed", StringComparison.Ordinal)),
            _ => query
        };

        DateTimeOffset? threshold = timeRangeFilter.ToLowerInvariant() switch
        {
            "1h" => nowUtc.AddHours(-1),
            "6h" => nowUtc.AddHours(-6),
            "24h" => nowUtc.AddHours(-24),
            "7d" => nowUtc.AddDays(-7),
            _ => null
        };

        if (threshold.HasValue)
        {
            query = query.Where(item => item.TimestampUtc >= threshold.Value);
        }

        return query
            .OrderByDescending(item => item.TimestampUtc)
            .ThenBy(item => item.DeviceName, StringComparer.Ordinal)
            .ThenBy(item => item.OperationName, StringComparer.Ordinal)
            .ToArray();
    }

    public static bool IsSuccess(AdminPkcs11TelemetryEntry item)
        => string.Equals(item.Status, "Succeeded", StringComparison.Ordinal);

    public static string GetStatusBadgeClass(AdminPkcs11TelemetryEntry item)
        => item.Status switch
        {
            "Succeeded" => "text-bg-success",
            "ReturnedFalse" => "text-bg-warning",
            _ => "text-bg-danger"
        };

    public static string FormatMechanism(ulong? value)
        => value.HasValue ? $"0x{value.Value:X}" : "—";

    public static string FormatDecimal(ulong? value)
        => value.HasValue ? value.Value.ToString(CultureInfo.InvariantCulture) : "—";

    private static bool MatchesNumericFilter(ulong? value, string filter)
    {
        if (!value.HasValue)
        {
            return false;
        }

        if (TryParseNumericFilter(filter, out ulong parsed))
        {
            return value.Value == parsed;
        }

        string decimalText = value.Value.ToString(CultureInfo.InvariantCulture);
        string hexText = FormatMechanism(value);
        return decimalText.Contains(filter, StringComparison.OrdinalIgnoreCase)
            || hexText.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseNumericFilter(string filter, out ulong value)
    {
        if (filter.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return ulong.TryParse(filter.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
        }

        return ulong.TryParse(filter, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool Contains(string? value, string term)
        => value?.Contains(term, StringComparison.OrdinalIgnoreCase) == true;
}
