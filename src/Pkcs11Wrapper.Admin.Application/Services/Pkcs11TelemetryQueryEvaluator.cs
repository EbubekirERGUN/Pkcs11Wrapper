using System.Globalization;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public static class Pkcs11TelemetryQueryEvaluator
{
    public static IReadOnlyList<AdminPkcs11TelemetryEntry> Apply(
        IReadOnlyList<AdminPkcs11TelemetryEntry> items,
        AdminPkcs11TelemetryQuery query,
        DateTimeOffset nowUtc)
    {
        IEnumerable<AdminPkcs11TelemetryEntry> filtered = items;

        if (!string.IsNullOrWhiteSpace(query.SearchText))
        {
            string term = query.SearchText.Trim();
            filtered = filtered.Where(item =>
                Contains(item.DeviceName, term)
                || Contains(item.OperationName, term)
                || Contains(item.NativeOperationName, term)
                || Contains(item.Status, term)
                || Contains(item.ReturnValue, term)
                || Contains(item.ExceptionType, term)
                || Contains(item.Actor, term)
                || Contains(item.AuthenticationType, term)
                || Contains(item.SessionId, term)
                || Contains(item.CorrelationId, term)
                || Contains(item.DeviceId.ToString("D"), term)
                || Contains(FormatDecimal(item.SlotId), term)
                || Contains(FormatDecimal(item.SessionHandle), term)
                || Contains(FormatMechanism(item.MechanismType), term)
                || FieldsContain(item.Fields, term));
        }

        if (!string.IsNullOrWhiteSpace(query.DeviceFilter))
        {
            filtered = filtered.Where(item => string.Equals(item.DeviceName, query.DeviceFilter, StringComparison.Ordinal));
        }

        if (!string.IsNullOrWhiteSpace(query.SlotFilter))
        {
            string slotTerm = query.SlotFilter.Trim();
            filtered = filtered.Where(item => MatchesNumericFilter(item.SlotId, slotTerm));
        }

        if (!string.IsNullOrWhiteSpace(query.OperationFilter))
        {
            filtered = filtered.Where(item => string.Equals(item.OperationName, query.OperationFilter, StringComparison.Ordinal));
        }

        if (!string.IsNullOrWhiteSpace(query.MechanismFilter))
        {
            string mechanismTerm = query.MechanismFilter.Trim();
            filtered = filtered.Where(item => MatchesNumericFilter(item.MechanismType, mechanismTerm));
        }

        if (query.MinDurationMilliseconds.HasValue && query.MinDurationMilliseconds.Value > 0)
        {
            filtered = filtered.Where(item => item.DurationMilliseconds >= query.MinDurationMilliseconds.Value);
        }

        string statusFilter = query.StatusFilter ?? "all";
        if (string.Equals(statusFilter, "success", StringComparison.OrdinalIgnoreCase))
            filtered = filtered.Where(IsSuccess);
        else if (string.Equals(statusFilter, "non-success", StringComparison.OrdinalIgnoreCase))
            filtered = filtered.Where(item => !IsSuccess(item));
        else if (string.Equals(statusFilter, "returned-false", StringComparison.OrdinalIgnoreCase))
            filtered = filtered.Where(item => string.Equals(item.Status, "ReturnedFalse", StringComparison.Ordinal));
        else if (string.Equals(statusFilter, "failed", StringComparison.OrdinalIgnoreCase))
            filtered = filtered.Where(item => string.Equals(item.Status, "Failed", StringComparison.Ordinal));

        string timeRange = query.TimeRangeFilter ?? "all";
        DateTimeOffset? threshold =
            string.Equals(timeRange, "1h", StringComparison.OrdinalIgnoreCase) ? nowUtc.AddHours(-1) :
            string.Equals(timeRange, "6h", StringComparison.OrdinalIgnoreCase) ? nowUtc.AddHours(-6) :
            string.Equals(timeRange, "24h", StringComparison.OrdinalIgnoreCase) ? nowUtc.AddHours(-24) :
            string.Equals(timeRange, "7d", StringComparison.OrdinalIgnoreCase) ? nowUtc.AddDays(-7) :
            null;

        if (threshold.HasValue)
        {
            filtered = filtered.Where(item => item.TimestampUtc >= threshold.Value);
        }

        return filtered
            .OrderByDescending(item => item.TimestampUtc)
            .ThenBy(item => item.DeviceName, StringComparer.Ordinal)
            .ThenBy(item => item.OperationName, StringComparer.Ordinal)
            .ToArray();
    }

    public static bool IsSuccess(AdminPkcs11TelemetryEntry item)
        => string.Equals(item.Status, "Succeeded", StringComparison.Ordinal);

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

    private static bool FieldsContain(IReadOnlyList<AdminPkcs11TelemetryField> fields, string term)
    {
        for (int i = 0; i < fields.Count; i++)
        {
            AdminPkcs11TelemetryField field = fields[i];
            if (Contains(field.Name, term) || Contains(field.Classification, term) || Contains(field.Value, term))
            {
                return true;
            }
        }
        return false;
    }
}
