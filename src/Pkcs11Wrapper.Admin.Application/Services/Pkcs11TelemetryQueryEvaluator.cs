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
                || Contains(item.DeviceId.ToString("D"), term)
                || Contains(item.OperationName, term)
                || Contains(item.NativeOperationName, term)
                || Contains(item.Status, term)
                || Contains(item.ReturnValue, term)
                || Contains(item.ExceptionType, term)
                || Contains(item.Actor, term)
                || Contains(item.AuthenticationType, term)
                || Contains(item.SessionId, term)
                || Contains(item.CorrelationId, term)
                || Contains(FormatDecimal(item.SlotId), term)
                || Contains(FormatDecimal(item.SessionHandle), term)
                || Contains(FormatMechanism(item.MechanismType), term)
                || item.Fields.Any(field =>
                    Contains(field.Name, term)
                    || Contains(field.Classification, term)
                    || Contains(field.Value, term)));
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

        filtered = (query.StatusFilter ?? "all").ToLowerInvariant() switch
        {
            "success" => filtered.Where(IsSuccess),
            "non-success" => filtered.Where(item => !IsSuccess(item)),
            "returned-false" => filtered.Where(item => string.Equals(item.Status, "ReturnedFalse", StringComparison.Ordinal)),
            "failed" => filtered.Where(item => string.Equals(item.Status, "Failed", StringComparison.Ordinal)),
            _ => filtered
        };

        DateTimeOffset? threshold = (query.TimeRangeFilter ?? "all").ToLowerInvariant() switch
        {
            "1h" => nowUtc.AddHours(-1),
            "6h" => nowUtc.AddHours(-6),
            "24h" => nowUtc.AddHours(-24),
            "7d" => nowUtc.AddDays(-7),
            _ => null
        };

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
}
