namespace Pkcs11Wrapper.Admin.Application.Models;

public static class HsmKeyObjectQuery
{
    public static IReadOnlyList<HsmKeyObjectSummary> Apply(
        IReadOnlyList<HsmKeyObjectSummary> keys,
        string? searchText,
        string classFilter,
        string capabilityFilter,
        string sortMode)
    {
        IEnumerable<HsmKeyObjectSummary> query = keys.Where(key => MatchesFilters(key, searchText, classFilter, capabilityFilter));
        return ApplySort(query, sortMode).ToArray();
    }

    public static bool MatchesFilters(HsmKeyObjectSummary key, string? searchText, string classFilter, string capabilityFilter)
        => MatchesSearch(key, searchText)
           && MatchesClassFilter(key, classFilter)
           && MatchesCapabilityFilter(key, capabilityFilter);

    public static bool MatchesSearch(HsmKeyObjectSummary key, string? searchText)
    {
        if (string.IsNullOrWhiteSpace(searchText))
        {
            return true;
        }

        string term = searchText.Trim();
        return key.Handle.ToString().Contains(term, StringComparison.OrdinalIgnoreCase)
               || Contains(key.Label, term)
               || Contains(key.IdHex, term)
               || Contains(key.ObjectClass, term)
               || Contains(key.KeyType, term);
    }

    public static bool MatchesClassFilter(HsmKeyObjectSummary key, string classFilter)
        => string.Equals(classFilter, "all", StringComparison.OrdinalIgnoreCase)
           || string.Equals(NormalizeClass(key.ObjectClass), classFilter, StringComparison.OrdinalIgnoreCase);

    public static bool MatchesCapabilityFilter(HsmKeyObjectSummary key, string capabilityFilter)
        => capabilityFilter.ToLowerInvariant() switch
        {
            "encrypt" => key.CanEncrypt == true,
            "decrypt" => key.CanDecrypt == true,
            "sign" => key.CanSign == true,
            "verify" => key.CanVerify == true,
            "wrap" => key.CanWrap == true,
            "unwrap" => key.CanUnwrap == true,
            _ => true
        };

    public static IOrderedEnumerable<HsmKeyObjectSummary> ApplySort(IEnumerable<HsmKeyObjectSummary> query, string sortMode)
        => sortMode.ToLowerInvariant() switch
        {
            "label" => query.OrderBy(key => key.Label ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .ThenBy(key => key.Handle),
            "class" => query.OrderBy(key => key.ObjectClass, StringComparer.OrdinalIgnoreCase)
                .ThenBy(key => key.Label ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .ThenBy(key => key.Handle),
            "capability" => query.OrderByDescending(GetCapabilityCount)
                .ThenBy(key => key.Label ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .ThenBy(key => key.Handle),
            _ => query.OrderBy(key => key.Handle)
        };

    public static int GetCapabilityCount(HsmKeyObjectSummary key)
    {
        int count = 0;
        if (key.CanEncrypt == true) count++;
        if (key.CanDecrypt == true) count++;
        if (key.CanSign == true) count++;
        if (key.CanVerify == true) count++;
        if (key.CanWrap == true) count++;
        if (key.CanUnwrap == true) count++;
        return count;
    }

    public static string NormalizeClass(string? objectClass)
        => string.IsNullOrWhiteSpace(objectClass)
            ? "other"
            : objectClass.Replace(" ", string.Empty, StringComparison.Ordinal).ToLowerInvariant() switch
            {
                "secretkey" => "secretkey",
                "privatekey" => "privatekey",
                "publickey" => "publickey",
                "data" => "data",
                _ => objectClass.Replace(" ", string.Empty, StringComparison.Ordinal).ToLowerInvariant()
            };

    private static bool Contains(string? value, string term)
        => value?.Contains(term, StringComparison.OrdinalIgnoreCase) == true;
}
