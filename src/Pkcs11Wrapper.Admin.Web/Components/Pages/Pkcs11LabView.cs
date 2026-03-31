using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Components.Pages;

public enum Pkcs11LabOperationCategory
{
    Diagnostics = 0,
    Crypto = 1,
    Objects = 2,
    Attributes = 3
}

public sealed record Pkcs11LabHistoryListItem(
    DateTimeOffset RecordedAt,
    Pkcs11LabOperation Operation,
    string Summary,
    bool Success,
    long DurationMilliseconds,
    Pkcs11LabArtifactKind ArtifactKind,
    string? CreatedHandleText,
    string? ArtifactHex);

public static class Pkcs11LabView
{
    public static Pkcs11LabOperationCategory GetCategory(Pkcs11LabOperation operation)
        => operation switch
        {
            Pkcs11LabOperation.ModuleInfo
                or Pkcs11LabOperation.InterfaceDiscovery
                or Pkcs11LabOperation.SlotSnapshot
                or Pkcs11LabOperation.MechanismList
                or Pkcs11LabOperation.MechanismInfo
                or Pkcs11LabOperation.SessionInfo
                or Pkcs11LabOperation.GenerateRandom
                or Pkcs11LabOperation.DigestText
                or Pkcs11LabOperation.FindObjects => Pkcs11LabOperationCategory.Diagnostics,

            Pkcs11LabOperation.SignData
                or Pkcs11LabOperation.VerifySignature
                or Pkcs11LabOperation.EncryptData
                or Pkcs11LabOperation.DecryptData => Pkcs11LabOperationCategory.Crypto,

            Pkcs11LabOperation.InspectObject
                or Pkcs11LabOperation.WrapKey
                or Pkcs11LabOperation.UnwrapAesKey => Pkcs11LabOperationCategory.Objects,

            Pkcs11LabOperation.ReadAttribute => Pkcs11LabOperationCategory.Attributes,
            _ => Pkcs11LabOperationCategory.Diagnostics
        };

    public static IReadOnlyList<Pkcs11LabHistoryListItem> ApplyHistoryFilters(
        IReadOnlyList<Pkcs11LabHistoryListItem> items,
        string? searchText,
        string statusFilter,
        string categoryFilter)
    {
        IEnumerable<Pkcs11LabHistoryListItem> query = items;

        if (!string.IsNullOrWhiteSpace(searchText))
        {
            string term = searchText.Trim();
            query = query.Where(item =>
                item.Operation.ToString().Contains(term, StringComparison.OrdinalIgnoreCase)
                || item.Summary.Contains(term, StringComparison.OrdinalIgnoreCase)
                || item.ArtifactKind.ToString().Contains(term, StringComparison.OrdinalIgnoreCase)
                || Contains(item.CreatedHandleText, term)
                || Contains(item.ArtifactHex, term));
        }

        query = statusFilter.ToLowerInvariant() switch
        {
            "success" => query.Where(item => item.Success),
            "failure" => query.Where(item => !item.Success),
            _ => query
        };

        query = categoryFilter.ToLowerInvariant() switch
        {
            "diagnostics" => query.Where(item => GetCategory(item.Operation) == Pkcs11LabOperationCategory.Diagnostics),
            "crypto" => query.Where(item => GetCategory(item.Operation) == Pkcs11LabOperationCategory.Crypto),
            "objects" => query.Where(item => GetCategory(item.Operation) == Pkcs11LabOperationCategory.Objects),
            "attributes" => query.Where(item => GetCategory(item.Operation) == Pkcs11LabOperationCategory.Attributes),
            _ => query
        };

        return query
            .OrderByDescending(item => item.RecordedAt)
            .ThenBy(item => item.Operation)
            .ToArray();
    }

    private static bool Contains(string? value, string term)
        => value?.Contains(term, StringComparison.OrdinalIgnoreCase) == true;
}
