using System.Text.Json;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Access;

public sealed class CryptoApiKeyOperationAuthorizationService(
    ICryptoApiSharedStateStore sharedStateStore,
    TimeProvider timeProvider)
{
    public async Task<CryptoApiKeyOperationAuthorizationResult> AuthorizeAsync(
        CryptoApiAuthenticatedClient authenticatedClient,
        string? aliasName,
        string? operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticatedClient);

        string normalizedAliasName = NormalizeAliasName(aliasName, nameof(aliasName));
        string normalizedOperation = CryptoApiOperationPolicyDocumentCodec.NormalizeOperation(operation, nameof(operation));

        CryptoApiSharedStateStatus status = await sharedStateStore.GetStatusAsync(cancellationToken);
        if (!status.Configured)
        {
            return Failed("Shared persistence is not configured.");
        }

        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiClientRecord? client = snapshot.Clients.FirstOrDefault(candidate => candidate.ClientId == authenticatedClient.ClientId);
        if (client is null || !client.IsEnabled)
        {
            return Failed("Authenticated Crypto API client is no longer enabled.");
        }

        CryptoApiKeyAliasRecord? alias = snapshot.KeyAliases.FirstOrDefault(candidate => string.Equals(candidate.AliasName, normalizedAliasName, StringComparison.OrdinalIgnoreCase));
        if (alias is null)
        {
            return Failed("Requested key alias was not found.");
        }

        if (!alias.IsEnabled)
        {
            return Failed("Requested key alias is disabled.");
        }

        HashSet<Guid> clientPolicyIds = snapshot.ClientPolicyBindings
            .Where(binding => binding.ClientId == authenticatedClient.ClientId)
            .Select(binding => binding.PolicyId)
            .ToHashSet();

        HashSet<Guid> aliasPolicyIds = snapshot.KeyAliasPolicyBindings
            .Where(binding => binding.AliasId == alias.AliasId)
            .Select(binding => binding.PolicyId)
            .ToHashSet();

        Guid[] sharedPolicyIds = clientPolicyIds.Intersect(aliasPolicyIds).ToArray();
        if (sharedPolicyIds.Length == 0)
        {
            return Failed("No shared policy grants this client access to the requested key alias.");
        }

        List<CryptoApiMatchedPolicy> matchedPolicies = [];
        foreach (CryptoApiPolicyRecord policy in snapshot.Policies.Where(candidate => sharedPolicyIds.Contains(candidate.PolicyId) && candidate.IsEnabled))
        {
            CryptoApiOperationPolicyDocument document;
            try
            {
                document = CryptoApiOperationPolicyDocumentCodec.Deserialize(policy.DocumentJson);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or JsonException)
            {
                return Failed($"Policy '{policy.PolicyName}' has an invalid document: {ex.Message}");
            }

            if (!CryptoApiOperationPolicyDocumentCodec.AllowsOperation(document, normalizedOperation))
            {
                continue;
            }

            matchedPolicies.Add(new CryptoApiMatchedPolicy(
                PolicyId: policy.PolicyId,
                PolicyName: policy.PolicyName,
                Revision: policy.Revision));
        }

        if (matchedPolicies.Count == 0)
        {
            return Failed("Requested operation is not allowed for this key alias.");
        }

        return new CryptoApiKeyOperationAuthorizationResult(
            Succeeded: true,
            FailureReason: null,
            Authorization: new CryptoApiAuthorizedKeyOperation(
                Client: authenticatedClient,
                Operation: normalizedOperation,
                AliasId: alias.AliasId,
                AliasName: alias.AliasName,
                ResolvedRoute: new CryptoApiResolvedKeyRoute(
                    DeviceRoute: alias.DeviceRoute,
                    SlotId: alias.SlotId,
                    ObjectLabel: alias.ObjectLabel,
                    ObjectIdHex: alias.ObjectIdHex),
                MatchedPolicies: matchedPolicies.OrderBy(policy => policy.PolicyName, StringComparer.OrdinalIgnoreCase).ToArray(),
                AuthorizedAtUtc: timeProvider.GetUtcNow()));
    }

    private static CryptoApiKeyOperationAuthorizationResult Failed(string reason)
        => new(
            Succeeded: false,
            FailureReason: reason,
            Authorization: null);

    private static string NormalizeAliasName(string? value, string parameterName)
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
