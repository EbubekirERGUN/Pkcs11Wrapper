using System.Text.Json;
using Pkcs11Wrapper.CryptoApi.Clients;

namespace Pkcs11Wrapper.CryptoApi.Access;

public sealed record CryptoApiKeyAccessSnapshot(
    bool SharedPersistenceConfigured,
    string SharedPersistenceProvider,
    string? ConnectionTarget,
    int SchemaVersion,
    IReadOnlyList<CryptoApiManagedKeyAlias> KeyAliases,
    IReadOnlyList<CryptoApiManagedPolicy> Policies);

public sealed record CryptoApiManagedKeyAlias(
    Guid AliasId,
    string AliasName,
    string? RouteGroupName,
    string? DeviceRoute,
    ulong? SlotId,
    string? ObjectLabel,
    string? ObjectIdHex,
    string? Notes,
    bool IsEnabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<Guid> BoundPolicyIds);

public sealed record CryptoApiManagedPolicy(
    Guid PolicyId,
    string PolicyName,
    string? Description,
    int Revision,
    IReadOnlyList<string> AllowedOperations,
    bool IsEnabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<Guid> BoundClientIds,
    IReadOnlyList<Guid> BoundAliasIds);

public sealed record CreateCryptoApiKeyAliasRequest(
    string AliasName,
    string? RouteGroupName,
    string? DeviceRoute,
    ulong? SlotId,
    string? ObjectLabel,
    string? ObjectIdHex,
    string? Notes);

public sealed record UpdateCryptoApiKeyAliasRequest(
    Guid AliasId,
    string AliasName,
    string? RouteGroupName,
    string? DeviceRoute,
    ulong? SlotId,
    string? ObjectLabel,
    string? ObjectIdHex,
    string? Notes);

public sealed record CreateCryptoApiPolicyRequest(
    string PolicyName,
    string? Description,
    IReadOnlyCollection<string> AllowedOperations);

public sealed record UpdateCryptoApiPolicyRequest(
    Guid PolicyId,
    string PolicyName,
    string? Description,
    IReadOnlyCollection<string> AllowedOperations);

public sealed record CryptoApiOperationPolicyDocument(
    int Version,
    IReadOnlyList<string> AllowedOperations);

public sealed record CryptoApiRouteCandidate(
    string? DeviceRoute,
    ulong SlotId,
    int Priority);

public sealed record CryptoApiRoutePlan(
    string? RouteGroupName,
    string SelectionMode,
    IReadOnlyList<CryptoApiRouteCandidate> Candidates,
    string? ObjectLabel,
    string? ObjectIdHex);

public sealed record CryptoApiResolvedKeyRoute(
    string? DeviceRoute,
    ulong SlotId,
    string? ObjectLabel,
    string? ObjectIdHex);

public sealed record CryptoApiMatchedPolicy(
    Guid PolicyId,
    string PolicyName,
    int Revision);

public sealed record CryptoApiAuthorizedKeyOperation(
    CryptoApiAuthenticatedClient Client,
    string Operation,
    Guid AliasId,
    string AliasName,
    CryptoApiRoutePlan RoutePlan,
    IReadOnlyList<CryptoApiMatchedPolicy> MatchedPolicies,
    DateTimeOffset AuthorizedAtUtc);

public sealed record CryptoApiKeyOperationAuthorizationResult(
    bool Succeeded,
    string? FailureReason,
    CryptoApiAuthorizedKeyOperation? Authorization);

public sealed record CryptoApiRequestAuthorizationResult(
    bool Succeeded,
    int? FailureStatusCode,
    string? FailureReason,
    CryptoApiAuthorizedKeyOperation? Authorization);

internal static class CryptoApiOperationPolicyDocumentCodec
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static string Serialize(IReadOnlyCollection<string> allowedOperations)
        => JsonSerializer.Serialize(
            new CryptoApiOperationPolicyDocument(
                Version: 1,
                AllowedOperations: NormalizeOperations(allowedOperations, nameof(allowedOperations))),
            SerializerOptions);

    public static CryptoApiOperationPolicyDocument Deserialize(string documentJson)
    {
        if (string.IsNullOrWhiteSpace(documentJson))
        {
            throw new InvalidOperationException("Policy document JSON is required.");
        }

        CryptoApiOperationPolicyDocument? document = JsonSerializer.Deserialize<CryptoApiOperationPolicyDocument>(documentJson, SerializerOptions);
        if (document is null)
        {
            throw new InvalidOperationException("Policy document JSON could not be parsed.");
        }

        if (document.Version != 1)
        {
            throw new InvalidOperationException($"Policy document version '{document.Version}' is not supported.");
        }

        return new CryptoApiOperationPolicyDocument(
            Version: 1,
            AllowedOperations: NormalizeOperations(document.AllowedOperations, nameof(document.AllowedOperations)));
    }

    public static bool AllowsOperation(CryptoApiOperationPolicyDocument document, string operation)
    {
        string normalizedOperation = NormalizeOperation(operation, nameof(operation));
        return document.AllowedOperations.Contains("*", StringComparer.Ordinal)
            || document.AllowedOperations.Contains(normalizedOperation, StringComparer.Ordinal);
    }

    public static string NormalizeOperation(string? value, string parameterName)
    {
        string normalized = NormalizeIdentifier(value, parameterName).ToLowerInvariant();
        if (normalized.Length > 64)
        {
            throw new ArgumentException("Value must be 64 characters or fewer.", parameterName);
        }

        return normalized;
    }

    private static string[] NormalizeOperations(IEnumerable<string>? values, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(values, parameterName);

        string[] normalized = values
            .Select(value => string.Equals(value?.Trim(), "*", StringComparison.Ordinal) ? "*" : NormalizeOperation(value, parameterName))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static value => value, StringComparer.Ordinal)
            .ToArray();

        if (normalized.Length == 0)
        {
            throw new ArgumentException("At least one allowed operation is required.", parameterName);
        }

        return normalized;
    }

    private static string NormalizeIdentifier(string? value, string parameterName)
    {
        string normalized = string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("Value is required.", parameterName)
            : value.Trim();

        foreach (char c in normalized)
        {
            if (!(char.IsLetterOrDigit(c) || c is '-' or '_' or '.'))
            {
                throw new ArgumentException("Only letters, digits, dash, underscore, and dot are allowed.", parameterName);
            }
        }

        return normalized;
    }
}
