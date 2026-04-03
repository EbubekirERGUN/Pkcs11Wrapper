using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Access;

public sealed class CryptoApiKeyAccessManagementService(
    ICryptoApiSharedStateStore sharedStateStore,
    TimeProvider timeProvider)
{
    public async Task<CryptoApiKeyAccessSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateStatus status = await sharedStateStore.GetStatusAsync(cancellationToken);
        if (!status.Configured)
        {
            return new CryptoApiKeyAccessSnapshot(
                SharedPersistenceConfigured: false,
                SharedPersistenceProvider: status.Provider,
                ConnectionTarget: status.ConnectionTarget,
                SchemaVersion: status.SchemaVersion,
                KeyAliases: [],
                Policies: []);
        }

        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        IReadOnlyDictionary<Guid, Guid[]> boundPoliciesByAlias = snapshot.KeyAliasPolicyBindings
            .GroupBy(binding => binding.AliasId)
            .ToDictionary(
                group => group.Key,
                group => group.Select(binding => binding.PolicyId).Distinct().OrderBy(id => id).ToArray());

        IReadOnlyDictionary<Guid, Guid[]> boundClientsByPolicy = snapshot.ClientPolicyBindings
            .GroupBy(binding => binding.PolicyId)
            .ToDictionary(
                group => group.Key,
                group => group.Select(binding => binding.ClientId).Distinct().OrderBy(id => id).ToArray());

        IReadOnlyDictionary<Guid, Guid[]> boundAliasesByPolicy = snapshot.KeyAliasPolicyBindings
            .GroupBy(binding => binding.PolicyId)
            .ToDictionary(
                group => group.Key,
                group => group.Select(binding => binding.AliasId).Distinct().OrderBy(id => id).ToArray());

        CryptoApiManagedKeyAlias[] aliases = snapshot.KeyAliases
            .OrderBy(alias => alias.AliasName, StringComparer.OrdinalIgnoreCase)
            .Select(alias => new CryptoApiManagedKeyAlias(
                AliasId: alias.AliasId,
                AliasName: alias.AliasName,
                DeviceRoute: alias.DeviceRoute,
                SlotId: alias.SlotId,
                ObjectLabel: alias.ObjectLabel,
                ObjectIdHex: alias.ObjectIdHex,
                Notes: alias.Notes,
                IsEnabled: alias.IsEnabled,
                CreatedAtUtc: alias.CreatedAtUtc,
                UpdatedAtUtc: alias.UpdatedAtUtc,
                BoundPolicyIds: boundPoliciesByAlias.TryGetValue(alias.AliasId, out Guid[]? policies) ? policies : []))
            .ToArray();

        CryptoApiManagedPolicy[] policies = snapshot.Policies
            .OrderBy(policy => policy.PolicyName, StringComparer.OrdinalIgnoreCase)
            .Select(policy =>
            {
                CryptoApiOperationPolicyDocument document = CryptoApiOperationPolicyDocumentCodec.Deserialize(policy.DocumentJson);
                return new CryptoApiManagedPolicy(
                    PolicyId: policy.PolicyId,
                    PolicyName: policy.PolicyName,
                    Description: policy.Description,
                    Revision: policy.Revision,
                    AllowedOperations: document.AllowedOperations,
                    IsEnabled: policy.IsEnabled,
                    CreatedAtUtc: policy.CreatedAtUtc,
                    UpdatedAtUtc: policy.UpdatedAtUtc,
                    BoundClientIds: boundClientsByPolicy.TryGetValue(policy.PolicyId, out Guid[]? clientIds) ? clientIds : [],
                    BoundAliasIds: boundAliasesByPolicy.TryGetValue(policy.PolicyId, out Guid[]? aliasIds) ? aliasIds : []);
            })
            .ToArray();

        return new CryptoApiKeyAccessSnapshot(
            SharedPersistenceConfigured: true,
            SharedPersistenceProvider: status.Provider,
            ConnectionTarget: status.ConnectionTarget,
            SchemaVersion: status.SchemaVersion,
            KeyAliases: aliases,
            Policies: policies);
    }

    public async Task<CryptoApiManagedKeyAlias> CreateKeyAliasAsync(CreateCryptoApiKeyAliasRequest request, CancellationToken cancellationToken = default)
    {
        string aliasName = NormalizeMachineName(request.AliasName, nameof(request.AliasName));
        string? deviceRoute = NormalizeOptionalMachineName(request.DeviceRoute, nameof(request.DeviceRoute));
        string? objectLabel = NormalizeOptionalText(request.ObjectLabel, 160, nameof(request.ObjectLabel));
        string? objectIdHex = NormalizeObjectIdHex(request.ObjectIdHex);
        EnsureRouteTarget(objectLabel, objectIdHex);

        DateTimeOffset now = timeProvider.GetUtcNow();
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        if (snapshot.KeyAliases.Any(alias => string.Equals(alias.AliasName, aliasName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A key alias named '{aliasName}' already exists.");
        }

        CryptoApiKeyAliasRecord record = new(
            AliasId: Guid.NewGuid(),
            AliasName: aliasName,
            DeviceRoute: deviceRoute,
            SlotId: request.SlotId,
            ObjectLabel: objectLabel,
            ObjectIdHex: objectIdHex,
            Notes: NormalizeOptionalText(request.Notes, 400, nameof(request.Notes)),
            IsEnabled: true,
            CreatedAtUtc: now,
            UpdatedAtUtc: now);

        await sharedStateStore.UpsertKeyAliasAsync(record, cancellationToken);
        return new CryptoApiManagedKeyAlias(
            AliasId: record.AliasId,
            AliasName: record.AliasName,
            DeviceRoute: record.DeviceRoute,
            SlotId: record.SlotId,
            ObjectLabel: record.ObjectLabel,
            ObjectIdHex: record.ObjectIdHex,
            Notes: record.Notes,
            IsEnabled: record.IsEnabled,
            CreatedAtUtc: record.CreatedAtUtc,
            UpdatedAtUtc: record.UpdatedAtUtc,
            BoundPolicyIds: []);
    }

    public async Task SetKeyAliasEnabledAsync(Guid aliasId, bool isEnabled, CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiKeyAliasRecord alias = snapshot.KeyAliases.FirstOrDefault(candidate => candidate.AliasId == aliasId)
            ?? throw new InvalidOperationException("Crypto API key alias was not found.");

        await sharedStateStore.UpsertKeyAliasAsync(alias with
        {
            IsEnabled = isEnabled,
            UpdatedAtUtc = timeProvider.GetUtcNow()
        }, cancellationToken);
    }

    public async Task<CryptoApiManagedPolicy> CreatePolicyAsync(CreateCryptoApiPolicyRequest request, CancellationToken cancellationToken = default)
    {
        string policyName = NormalizeMachineName(request.PolicyName, nameof(request.PolicyName));
        string[] allowedOperations = request.AllowedOperations
            .Select(operation => string.Equals(operation?.Trim(), "*", StringComparison.Ordinal) ? "*" : CryptoApiOperationPolicyDocumentCodec.NormalizeOperation(operation, nameof(request.AllowedOperations)))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static value => value, StringComparer.Ordinal)
            .ToArray();

        if (allowedOperations.Length == 0)
        {
            throw new ArgumentException("At least one allowed operation is required.", nameof(request.AllowedOperations));
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        if (snapshot.Policies.Any(policy => string.Equals(policy.PolicyName, policyName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A policy named '{policyName}' already exists.");
        }

        CryptoApiPolicyRecord record = new(
            PolicyId: Guid.NewGuid(),
            PolicyName: policyName,
            Description: NormalizeOptionalText(request.Description, 400, nameof(request.Description)),
            Revision: 1,
            DocumentJson: CryptoApiOperationPolicyDocumentCodec.Serialize(allowedOperations),
            IsEnabled: true,
            CreatedAtUtc: now,
            UpdatedAtUtc: now);

        await sharedStateStore.UpsertPolicyAsync(record, cancellationToken);
        return new CryptoApiManagedPolicy(
            PolicyId: record.PolicyId,
            PolicyName: record.PolicyName,
            Description: record.Description,
            Revision: record.Revision,
            AllowedOperations: allowedOperations,
            IsEnabled: record.IsEnabled,
            CreatedAtUtc: record.CreatedAtUtc,
            UpdatedAtUtc: record.UpdatedAtUtc,
            BoundClientIds: [],
            BoundAliasIds: []);
    }

    public async Task SetPolicyEnabledAsync(Guid policyId, bool isEnabled, CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiPolicyRecord policy = snapshot.Policies.FirstOrDefault(candidate => candidate.PolicyId == policyId)
            ?? throw new InvalidOperationException("Crypto API policy was not found.");

        await sharedStateStore.UpsertPolicyAsync(policy with
        {
            IsEnabled = isEnabled,
            UpdatedAtUtc = timeProvider.GetUtcNow()
        }, cancellationToken);
    }

    public async Task ReplaceClientPoliciesAsync(Guid clientId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        _ = snapshot.Clients.FirstOrDefault(client => client.ClientId == clientId)
            ?? throw new InvalidOperationException("Crypto API client was not found.");

        EnsurePoliciesExist(snapshot, policyIds);
        await sharedStateStore.ReplaceClientPolicyBindingsAsync(clientId, policyIds, cancellationToken);
    }

    public async Task ReplaceKeyAliasPoliciesAsync(Guid aliasId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        _ = snapshot.KeyAliases.FirstOrDefault(alias => alias.AliasId == aliasId)
            ?? throw new InvalidOperationException("Crypto API key alias was not found.");

        EnsurePoliciesExist(snapshot, policyIds);
        await sharedStateStore.ReplaceKeyAliasPolicyBindingsAsync(aliasId, policyIds, cancellationToken);
    }

    private static void EnsurePoliciesExist(CryptoApiSharedStateSnapshot snapshot, IReadOnlyCollection<Guid> policyIds)
    {
        HashSet<Guid> knownPolicyIds = snapshot.Policies.Select(policy => policy.PolicyId).ToHashSet();
        foreach (Guid policyId in policyIds.Distinct())
        {
            if (!knownPolicyIds.Contains(policyId))
            {
                throw new InvalidOperationException($"Crypto API policy '{policyId}' was not found.");
            }
        }
    }

    private static void EnsureRouteTarget(string? objectLabel, string? objectIdHex)
    {
        if (objectLabel is null && objectIdHex is null)
        {
            throw new ArgumentException("Either an object label or object id hex value is required to route an alias.");
        }
    }

    private static string NormalizeMachineName(string? value, string parameterName)
    {
        string normalized = NormalizeOptionalText(value, 120, parameterName)
            ?? throw new ArgumentException("Value is required.", parameterName);

        foreach (char c in normalized)
        {
            if (!(char.IsLetterOrDigit(c) || c is '-' or '_' or '.'))
            {
                throw new ArgumentException("Only letters, digits, dash, underscore, and dot are allowed.", parameterName);
            }
        }

        return normalized;
    }

    private static string? NormalizeOptionalMachineName(string? value, string parameterName)
        => value is null ? null : NormalizeMachineName(value, parameterName);

    private static string? NormalizeOptionalText(string? value, int maxLength, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string normalized = value.Trim();
        if (normalized.Length > maxLength)
        {
            throw new ArgumentException($"Value must be {maxLength} characters or fewer.", parameterName);
        }

        return normalized;
    }

    private static string? NormalizeObjectIdHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        char[] filtered = value.Trim()
            .Where(static c => !char.IsWhiteSpace(c) && c is not '-' and not ':')
            .ToArray();

        if (filtered.Length == 0)
        {
            return null;
        }

        if (filtered.Length % 2 != 0)
        {
            throw new ArgumentException("Object id hex must contain an even number of hexadecimal characters.", nameof(value));
        }

        foreach (char c in filtered)
        {
            if (!Uri.IsHexDigit(c))
            {
                throw new ArgumentException("Object id hex must contain only hexadecimal characters.", nameof(value));
            }
        }

        return new string(filtered).ToUpperInvariant();
    }
}
