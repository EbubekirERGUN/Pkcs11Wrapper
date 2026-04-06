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
        Dictionary<Guid, HashSet<Guid>> policiesByAlias = new(snapshot.KeyAliasPolicyBindings.Count);
        Dictionary<Guid, HashSet<Guid>> aliasesByPolicy = new(snapshot.KeyAliasPolicyBindings.Count);
        foreach (var binding in snapshot.KeyAliasPolicyBindings)
        {
            if (!policiesByAlias.TryGetValue(binding.AliasId, out HashSet<Guid>? policySet))
            {
                policySet = [];
                policiesByAlias[binding.AliasId] = policySet;
            }
            policySet.Add(binding.PolicyId);

            if (!aliasesByPolicy.TryGetValue(binding.PolicyId, out HashSet<Guid>? aliasSet))
            {
                aliasSet = [];
                aliasesByPolicy[binding.PolicyId] = aliasSet;
            }
            aliasSet.Add(binding.AliasId);
        }

        Dictionary<Guid, HashSet<Guid>> clientsByPolicy = new(snapshot.ClientPolicyBindings.Count);
        foreach (var binding in snapshot.ClientPolicyBindings)
        {
            if (!clientsByPolicy.TryGetValue(binding.PolicyId, out HashSet<Guid>? clientSet))
            {
                clientSet = [];
                clientsByPolicy[binding.PolicyId] = clientSet;
            }
            clientSet.Add(binding.ClientId);
        }

        CryptoApiManagedKeyAlias[] aliases = new CryptoApiManagedKeyAlias[snapshot.KeyAliases.Count];
        List<CryptoApiKeyAliasRecord> sortedAliases = [.. snapshot.KeyAliases];
        sortedAliases.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.AliasName, b.AliasName));
        for (int i = 0; i < sortedAliases.Count; i++)
        {
            CryptoApiKeyAliasRecord alias = sortedAliases[i];
            Guid[] policyIds = policiesByAlias.TryGetValue(alias.AliasId, out HashSet<Guid>? pSet) ? ToSortedArray(pSet) : [];
            aliases[i] = MapAlias(alias, policyIds);
        }

        CryptoApiManagedPolicy[] policies = new CryptoApiManagedPolicy[snapshot.Policies.Count];
        List<CryptoApiPolicyRecord> sortedPolicies = [.. snapshot.Policies];
        sortedPolicies.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.PolicyName, b.PolicyName));
        for (int i = 0; i < sortedPolicies.Count; i++)
        {
            CryptoApiPolicyRecord policy = sortedPolicies[i];
            Guid[] clientIds = clientsByPolicy.TryGetValue(policy.PolicyId, out HashSet<Guid>? cSet) ? ToSortedArray(cSet) : [];
            Guid[] aliasIds = aliasesByPolicy.TryGetValue(policy.PolicyId, out HashSet<Guid>? aSet) ? ToSortedArray(aSet) : [];
            policies[i] = MapPolicy(policy, clientIds, aliasIds);
        }

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
        string? routeGroupName = NormalizeOptionalMachineName(request.RouteGroupName, nameof(request.RouteGroupName));
        string? deviceRoute = NormalizeOptionalMachineName(request.DeviceRoute, nameof(request.DeviceRoute));
        ulong? slotId = request.SlotId;
        string? objectLabel = NormalizeOptionalText(request.ObjectLabel, 160, nameof(request.ObjectLabel));
        string? objectIdHex = NormalizeObjectIdHex(request.ObjectIdHex);
        ValidateAliasRouteDefinition(routeGroupName, deviceRoute, slotId, objectLabel, objectIdHex);

        DateTimeOffset now = timeProvider.GetUtcNow();
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        if (snapshot.KeyAliases.Any(alias => string.Equals(alias.AliasName, aliasName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A key alias named '{aliasName}' already exists.");
        }

        CryptoApiKeyAliasRecord record = new(
            AliasId: Guid.NewGuid(),
            AliasName: aliasName,
            RouteGroupName: routeGroupName,
            DeviceRoute: routeGroupName is null ? deviceRoute : null,
            SlotId: routeGroupName is null ? slotId : null,
            ObjectLabel: objectLabel,
            ObjectIdHex: objectIdHex,
            Notes: NormalizeOptionalText(request.Notes, 400, nameof(request.Notes)),
            IsEnabled: true,
            CreatedAtUtc: now,
            UpdatedAtUtc: now);

        await sharedStateStore.UpsertKeyAliasAsync(record, cancellationToken);
        return MapAlias(record, []);
    }

    public async Task<CryptoApiManagedKeyAlias> UpdateKeyAliasAsync(UpdateCryptoApiKeyAliasRequest request, CancellationToken cancellationToken = default)
    {
        string aliasName = NormalizeMachineName(request.AliasName, nameof(request.AliasName));
        string? routeGroupName = NormalizeOptionalMachineName(request.RouteGroupName, nameof(request.RouteGroupName));
        string? deviceRoute = NormalizeOptionalMachineName(request.DeviceRoute, nameof(request.DeviceRoute));
        ulong? slotId = request.SlotId;
        string? objectLabel = NormalizeOptionalText(request.ObjectLabel, 160, nameof(request.ObjectLabel));
        string? objectIdHex = NormalizeObjectIdHex(request.ObjectIdHex);
        ValidateAliasRouteDefinition(routeGroupName, deviceRoute, slotId, objectLabel, objectIdHex);

        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiKeyAliasRecord existing = snapshot.KeyAliases.FirstOrDefault(candidate => candidate.AliasId == request.AliasId)
            ?? throw new InvalidOperationException("Crypto API key alias was not found.");

        if (snapshot.KeyAliases.Any(alias => alias.AliasId != request.AliasId && string.Equals(alias.AliasName, aliasName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A key alias named '{aliasName}' already exists.");
        }

        CryptoApiKeyAliasRecord updated = existing with
        {
            AliasName = aliasName,
            RouteGroupName = routeGroupName,
            DeviceRoute = routeGroupName is null ? deviceRoute : null,
            SlotId = routeGroupName is null ? slotId : null,
            ObjectLabel = objectLabel,
            ObjectIdHex = objectIdHex,
            Notes = NormalizeOptionalText(request.Notes, 400, nameof(request.Notes)),
            UpdatedAtUtc = timeProvider.GetUtcNow()
        };

        await sharedStateStore.UpsertKeyAliasAsync(updated, cancellationToken);
        return MapAlias(updated, GetBoundPolicyIds(snapshot, updated.AliasId));
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
        string[] allowedOperations = NormalizeAllowedOperations(request.AllowedOperations, nameof(request.AllowedOperations));

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
        return MapPolicy(record, [], []);
    }

    public async Task<CryptoApiManagedPolicy> UpdatePolicyAsync(UpdateCryptoApiPolicyRequest request, CancellationToken cancellationToken = default)
    {
        string policyName = NormalizeMachineName(request.PolicyName, nameof(request.PolicyName));
        string? description = NormalizeOptionalText(request.Description, 400, nameof(request.Description));
        string[] allowedOperations = NormalizeAllowedOperations(request.AllowedOperations, nameof(request.AllowedOperations));
        string documentJson = CryptoApiOperationPolicyDocumentCodec.Serialize(allowedOperations);

        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiPolicyRecord existing = snapshot.Policies.FirstOrDefault(candidate => candidate.PolicyId == request.PolicyId)
            ?? throw new InvalidOperationException("Crypto API policy was not found.");

        if (snapshot.Policies.Any(policy => policy.PolicyId != request.PolicyId && string.Equals(policy.PolicyName, policyName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A policy named '{policyName}' already exists.");
        }

        bool changed = !string.Equals(existing.PolicyName, policyName, StringComparison.Ordinal)
            || !string.Equals(existing.Description, description, StringComparison.Ordinal)
            || !string.Equals(existing.DocumentJson, documentJson, StringComparison.Ordinal);

        CryptoApiPolicyRecord updated = existing with
        {
            PolicyName = policyName,
            Description = description,
            Revision = changed ? existing.Revision + 1 : existing.Revision,
            DocumentJson = documentJson,
            UpdatedAtUtc = timeProvider.GetUtcNow()
        };

        await sharedStateStore.UpsertPolicyAsync(updated, cancellationToken);
        return MapPolicy(updated, GetBoundClientIds(snapshot, updated.PolicyId), GetBoundAliasIds(snapshot, updated.PolicyId));
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

    private static CryptoApiManagedKeyAlias MapAlias(CryptoApiKeyAliasRecord alias, IReadOnlyList<Guid> boundPolicyIds)
        => new(
            AliasId: alias.AliasId,
            AliasName: alias.AliasName,
            RouteGroupName: alias.RouteGroupName,
            DeviceRoute: alias.DeviceRoute,
            SlotId: alias.SlotId,
            ObjectLabel: alias.ObjectLabel,
            ObjectIdHex: alias.ObjectIdHex,
            Notes: alias.Notes,
            IsEnabled: alias.IsEnabled,
            CreatedAtUtc: alias.CreatedAtUtc,
            UpdatedAtUtc: alias.UpdatedAtUtc,
            BoundPolicyIds: boundPolicyIds);

    private static CryptoApiManagedPolicy MapPolicy(CryptoApiPolicyRecord policy, IReadOnlyList<Guid> boundClientIds, IReadOnlyList<Guid> boundAliasIds)
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
            BoundClientIds: boundClientIds,
            BoundAliasIds: boundAliasIds);
    }

    private static Guid[] GetBoundPolicyIds(CryptoApiSharedStateSnapshot snapshot, Guid aliasId)
    {
        HashSet<Guid>? ids = null;
        foreach (var binding in snapshot.KeyAliasPolicyBindings)
        {
            if (binding.AliasId == aliasId)
            {
                ids ??= [];
                ids.Add(binding.PolicyId);
            }
        }
        return ids is null ? [] : ToSortedArray(ids);
    }

    private static Guid[] GetBoundClientIds(CryptoApiSharedStateSnapshot snapshot, Guid policyId)
    {
        HashSet<Guid>? ids = null;
        foreach (var binding in snapshot.ClientPolicyBindings)
        {
            if (binding.PolicyId == policyId)
            {
                ids ??= [];
                ids.Add(binding.ClientId);
            }
        }
        return ids is null ? [] : ToSortedArray(ids);
    }

    private static Guid[] GetBoundAliasIds(CryptoApiSharedStateSnapshot snapshot, Guid policyId)
    {
        HashSet<Guid>? ids = null;
        foreach (var binding in snapshot.KeyAliasPolicyBindings)
        {
            if (binding.PolicyId == policyId)
            {
                ids ??= [];
                ids.Add(binding.AliasId);
            }
        }
        return ids is null ? [] : ToSortedArray(ids);
    }

    private static Guid[] ToSortedArray(HashSet<Guid> set)
    {
        Guid[] result = [.. set];
        Array.Sort(result);
        return result;
    }

    private static string[] NormalizeAllowedOperations(IReadOnlyCollection<string> allowedOperations, string parameterName)
    {
        string[] normalized = allowedOperations
            .Select(operation => string.Equals(operation?.Trim(), "*", StringComparison.Ordinal)
                ? "*"
                : CryptoApiOperationPolicyDocumentCodec.NormalizeOperation(operation, parameterName))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static value => value, StringComparer.Ordinal)
            .ToArray();

        if (normalized.Length == 0)
        {
            throw new ArgumentException("At least one allowed operation is required.", parameterName);
        }

        return normalized;
    }

    private static void EnsurePoliciesExist(CryptoApiSharedStateSnapshot snapshot, IReadOnlyCollection<Guid> policyIds)
    {
        HashSet<Guid> knownPolicyIds = new(snapshot.Policies.Count);
        foreach (var policy in snapshot.Policies)
        {
            knownPolicyIds.Add(policy.PolicyId);
        }

        HashSet<Guid>? seen = policyIds.Count > 1 ? new(policyIds.Count) : null;
        foreach (Guid policyId in policyIds)
        {
            if (seen is not null && !seen.Add(policyId))
            {
                continue;
            }

            if (!knownPolicyIds.Contains(policyId))
            {
                throw new InvalidOperationException($"Crypto API policy '{policyId}' was not found.");
            }
        }
    }

    private static void ValidateAliasRouteDefinition(string? routeGroupName, string? deviceRoute, ulong? slotId, string? objectLabel, string? objectIdHex)
    {
        EnsureRouteTarget(objectLabel, objectIdHex);

        if (routeGroupName is not null)
        {
            if (deviceRoute is not null || slotId is not null)
            {
                throw new ArgumentException("Specify either a route group name or a legacy device-route/slot binding, not both.");
            }

            return;
        }

        _ = slotId ?? throw new ArgumentException("A PKCS#11 slot id is required when an alias does not target a route group.");
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

        ReadOnlySpan<char> trimmed = value.AsSpan().Trim();
        Span<char> buffer = trimmed.Length <= 256 ? stackalloc char[trimmed.Length] : new char[trimmed.Length];
        int count = 0;
        foreach (char c in trimmed)
        {
            if (!char.IsWhiteSpace(c) && c is not '-' and not ':')
            {
                buffer[count++] = char.ToUpperInvariant(c);
            }
        }

        if (count == 0)
        {
            return null;
        }

        if (count % 2 != 0)
        {
            throw new ArgumentException("Object id hex must contain an even number of hexadecimal characters.", nameof(value));
        }

        ReadOnlySpan<char> result = buffer[..count];
        foreach (char c in result)
        {
            if (!Uri.IsHexDigit(c))
            {
                throw new ArgumentException("Object id hex must contain only hexadecimal characters.", nameof(value));
            }
        }

        return new string(result);
    }
}
