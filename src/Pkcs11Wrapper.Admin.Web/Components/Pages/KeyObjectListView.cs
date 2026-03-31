using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Components.Pages;

public static class KeyObjectListView
{
    public static IReadOnlyList<HsmKeyObjectSummary> Apply(
        IReadOnlyList<HsmKeyObjectSummary> keys,
        string? searchText,
        string classFilter,
        string capabilityFilter,
        string sortMode)
    {
        IEnumerable<HsmKeyObjectSummary> query = keys;

        if (!string.IsNullOrWhiteSpace(searchText))
        {
            string term = searchText.Trim();
            query = query.Where(key =>
                key.Handle.ToString().Contains(term, StringComparison.OrdinalIgnoreCase)
                || Contains(key.Label, term)
                || Contains(key.IdHex, term)
                || Contains(key.ObjectClass, term)
                || Contains(key.KeyType, term));
        }

        if (!string.Equals(classFilter, "all", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(key => string.Equals(Normalize(key.ObjectClass), classFilter, StringComparison.OrdinalIgnoreCase));
        }

        query = capabilityFilter.ToLowerInvariant() switch
        {
            "encrypt" => query.Where(key => key.CanEncrypt == true),
            "decrypt" => query.Where(key => key.CanDecrypt == true),
            "sign" => query.Where(key => key.CanSign == true),
            "verify" => query.Where(key => key.CanVerify == true),
            "wrap" => query.Where(key => key.CanWrap == true),
            "unwrap" => query.Where(key => key.CanUnwrap == true),
            _ => query
        };

        query = sortMode.ToLowerInvariant() switch
        {
            "label" => query.OrderBy(key => key.Label ?? string.Empty, StringComparer.OrdinalIgnoreCase).ThenBy(key => key.Handle),
            "class" => query.OrderBy(key => key.ObjectClass, StringComparer.OrdinalIgnoreCase).ThenBy(key => key.Label ?? string.Empty, StringComparer.OrdinalIgnoreCase).ThenBy(key => key.Handle),
            "capability" => query.OrderByDescending(GetCapabilityCount).ThenBy(key => key.Label ?? string.Empty, StringComparer.OrdinalIgnoreCase).ThenBy(key => key.Handle),
            _ => query.OrderBy(key => key.Handle)
        };

        return query.ToArray();
    }

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

    public static string Normalize(string? objectClass)
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
