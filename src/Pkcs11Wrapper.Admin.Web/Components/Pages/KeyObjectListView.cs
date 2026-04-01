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
        => HsmKeyObjectQuery.Apply(keys, searchText, classFilter, capabilityFilter, sortMode);

    public static int GetCapabilityCount(HsmKeyObjectSummary key)
        => HsmKeyObjectQuery.GetCapabilityCount(key);

    public static string Normalize(string? objectClass)
        => HsmKeyObjectQuery.NormalizeClass(objectClass);
}
