using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Clients;

public sealed class CryptoApiClientManagementService(
    ICryptoApiSharedStateStore sharedStateStore,
    CryptoApiClientSecretGenerator secretGenerator,
    CryptoApiClientSecretHasher secretHasher,
    TimeProvider timeProvider)
{
    public async Task<CryptoApiClientManagementSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateStatus status = await sharedStateStore.GetStatusAsync(cancellationToken);
        if (!status.Configured)
        {
            return new CryptoApiClientManagementSnapshot(
                SharedPersistenceConfigured: false,
                SharedPersistenceProvider: status.Provider,
                ConnectionTarget: status.ConnectionTarget,
                SchemaVersion: status.SchemaVersion,
                Clients: []);
        }

        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        IReadOnlyDictionary<Guid, Guid[]> boundPoliciesByClient = snapshot.ClientPolicyBindings
            .GroupBy(binding => binding.ClientId)
            .ToDictionary(
                group => group.Key,
                group => group.Select(binding => binding.PolicyId).Distinct().OrderBy(id => id).ToArray());

        IReadOnlyDictionary<Guid, CryptoApiManagedClientKey[]> keysByClient = snapshot.ClientKeys
            .GroupBy(key => key.ClientId)
            .ToDictionary(
                group => group.Key,
                group => group.OrderByDescending(key => key.CreatedAtUtc)
                    .ThenBy(key => key.KeyName, StringComparer.OrdinalIgnoreCase)
                    .Select(MapKey)
                    .ToArray());

        CryptoApiManagedClient[] clients = snapshot.Clients
            .OrderBy(client => client.ClientName, StringComparer.OrdinalIgnoreCase)
            .Select(client => new CryptoApiManagedClient(
                ClientId: client.ClientId,
                ClientName: client.ClientName,
                DisplayName: client.DisplayName,
                ApplicationType: client.ApplicationType,
                AuthenticationMode: client.AuthenticationMode,
                IsEnabled: client.IsEnabled,
                Notes: client.Notes,
                CreatedAtUtc: client.CreatedAtUtc,
                UpdatedAtUtc: client.UpdatedAtUtc,
                BoundPolicyIds: boundPoliciesByClient.TryGetValue(client.ClientId, out Guid[]? policies) ? policies : [],
                Keys: keysByClient.TryGetValue(client.ClientId, out CryptoApiManagedClientKey[]? keys) ? keys : []))
            .ToArray();

        return new CryptoApiClientManagementSnapshot(
            SharedPersistenceConfigured: true,
            SharedPersistenceProvider: status.Provider,
            ConnectionTarget: status.ConnectionTarget,
            SchemaVersion: status.SchemaVersion,
            Clients: clients);
    }

    public async Task<CryptoApiManagedClient> CreateClientAsync(CreateCryptoApiClientRequest request, CancellationToken cancellationToken = default)
    {
        string clientName = NormalizeName(request.ClientName, nameof(request.ClientName));
        string displayName = NormalizeDisplayName(request.DisplayName, clientName);
        string applicationType = NormalizeApplicationType(request.ApplicationType);
        DateTimeOffset now = timeProvider.GetUtcNow();

        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        if (snapshot.Clients.Any(client => string.Equals(client.ClientName, clientName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A Crypto API client named '{clientName}' already exists.");
        }

        CryptoApiClientRecord record = new(
            ClientId: Guid.NewGuid(),
            ClientName: clientName,
            DisplayName: displayName,
            ApplicationType: applicationType,
            AuthenticationMode: CryptoApiAuthenticationDefaults.ApiKeyAuthenticationMode,
            IsEnabled: true,
            Notes: NormalizeOptional(request.Notes),
            CreatedAtUtc: now,
            UpdatedAtUtc: now);

        await sharedStateStore.UpsertClientAsync(record, cancellationToken);
        return new CryptoApiManagedClient(
            ClientId: record.ClientId,
            ClientName: record.ClientName,
            DisplayName: record.DisplayName,
            ApplicationType: record.ApplicationType,
            AuthenticationMode: record.AuthenticationMode,
            IsEnabled: record.IsEnabled,
            Notes: record.Notes,
            CreatedAtUtc: record.CreatedAtUtc,
            UpdatedAtUtc: record.UpdatedAtUtc,
            BoundPolicyIds: [],
            Keys: []);
    }

    public async Task SetClientEnabledAsync(Guid clientId, bool isEnabled, CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiClientRecord client = snapshot.Clients.FirstOrDefault(candidate => candidate.ClientId == clientId)
            ?? throw new InvalidOperationException("Crypto API client was not found.");

        await sharedStateStore.UpsertClientAsync(client with
        {
            IsEnabled = isEnabled,
            UpdatedAtUtc = timeProvider.GetUtcNow()
        }, cancellationToken);
    }

    public async Task<CryptoApiCreatedClientKey> CreateClientKeyAsync(CreateCryptoApiClientKeyRequest request, CancellationToken cancellationToken = default)
    {
        string keyName = NormalizeDisplayName(request.KeyName, "api-key");
        DateTimeOffset now = timeProvider.GetUtcNow();
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);

        CryptoApiClientRecord client = snapshot.Clients.FirstOrDefault(candidate => candidate.ClientId == request.ClientId)
            ?? throw new InvalidOperationException("Crypto API client was not found.");

        if (snapshot.ClientKeys.Any(key => key.ClientId == request.ClientId && string.Equals(key.KeyName, keyName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"Client '{client.ClientName}' already has a key named '{keyName}'.");
        }

        string secret = secretGenerator.GenerateSecret();
        string keyIdentifier = secretGenerator.GenerateKeyIdentifier();
        CryptoApiClientKeyRecord record = new(
            ClientKeyId: Guid.NewGuid(),
            ClientId: request.ClientId,
            KeyName: keyName,
            KeyIdentifier: keyIdentifier,
            CredentialType: CryptoApiAuthenticationDefaults.ApiKeyCredentialType,
            SecretHashAlgorithm: CryptoApiClientSecretHasher.Algorithm,
            SecretHash: secretHasher.HashSecret(secret),
            SecretHint: secretGenerator.BuildSecretHint(secret),
            IsEnabled: true,
            CreatedAtUtc: now,
            UpdatedAtUtc: now,
            ExpiresAtUtc: request.ExpiresAtUtc?.ToUniversalTime(),
            RevokedAtUtc: null,
            RevokedReason: null,
            LastUsedAtUtc: null);

        await sharedStateStore.UpsertClientKeyAsync(record, cancellationToken);
        return new CryptoApiCreatedClientKey(
            ClientKeyId: record.ClientKeyId,
            ClientId: record.ClientId,
            KeyName: record.KeyName,
            KeyIdentifier: record.KeyIdentifier,
            Secret: secret,
            SecretHint: record.SecretHint,
            SecretHashAlgorithm: record.SecretHashAlgorithm,
            CreatedAtUtc: record.CreatedAtUtc,
            ExpiresAtUtc: record.ExpiresAtUtc);
    }

    public async Task SetClientKeyEnabledAsync(Guid clientKeyId, bool isEnabled, CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiClientKeyRecord key = snapshot.ClientKeys.FirstOrDefault(candidate => candidate.ClientKeyId == clientKeyId)
            ?? throw new InvalidOperationException("Crypto API client key was not found.");

        await sharedStateStore.UpsertClientKeyAsync(key with
        {
            IsEnabled = isEnabled,
            UpdatedAtUtc = timeProvider.GetUtcNow()
        }, cancellationToken);
    }

    public async Task SetClientKeyExpiryAsync(Guid clientKeyId, DateTimeOffset? expiresAtUtc, CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiClientKeyRecord key = snapshot.ClientKeys.FirstOrDefault(candidate => candidate.ClientKeyId == clientKeyId)
            ?? throw new InvalidOperationException("Crypto API client key was not found.");

        await sharedStateStore.UpsertClientKeyAsync(key with
        {
            ExpiresAtUtc = expiresAtUtc?.ToUniversalTime(),
            UpdatedAtUtc = timeProvider.GetUtcNow()
        }, cancellationToken);
    }

    public async Task RevokeClientKeyAsync(Guid clientKeyId, string? reason = null, CancellationToken cancellationToken = default)
    {
        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiClientKeyRecord key = snapshot.ClientKeys.FirstOrDefault(candidate => candidate.ClientKeyId == clientKeyId)
            ?? throw new InvalidOperationException("Crypto API client key was not found.");

        DateTimeOffset now = timeProvider.GetUtcNow();
        await sharedStateStore.UpsertClientKeyAsync(key with
        {
            IsEnabled = false,
            RevokedAtUtc = key.RevokedAtUtc ?? now,
            RevokedReason = NormalizeOptional(reason) ?? "Revoked from the admin control plane.",
            UpdatedAtUtc = now
        }, cancellationToken);
    }

    private static CryptoApiManagedClientKey MapKey(CryptoApiClientKeyRecord key)
        => new(
            ClientKeyId: key.ClientKeyId,
            ClientId: key.ClientId,
            KeyName: key.KeyName,
            KeyIdentifier: key.KeyIdentifier,
            CredentialType: key.CredentialType,
            SecretHashAlgorithm: key.SecretHashAlgorithm,
            SecretHint: key.SecretHint,
            IsEnabled: key.IsEnabled,
            CreatedAtUtc: key.CreatedAtUtc,
            UpdatedAtUtc: key.UpdatedAtUtc,
            ExpiresAtUtc: key.ExpiresAtUtc,
            RevokedAtUtc: key.RevokedAtUtc,
            RevokedReason: key.RevokedReason,
            LastUsedAtUtc: key.LastUsedAtUtc);

    private static string NormalizeName(string? value, string parameterName)
    {
        string normalized = NormalizeOptional(value) ?? throw new ArgumentException("Value is required.", parameterName);
        if (normalized.Length > 120)
        {
            throw new ArgumentException("Value must be 120 characters or fewer.", parameterName);
        }

        foreach (char c in normalized)
        {
            if (!(char.IsLetterOrDigit(c) || c is '-' or '_' or '.'))
            {
                throw new ArgumentException("Only letters, digits, dash, underscore, and dot are allowed.", parameterName);
            }
        }

        return normalized;
    }

    private static string NormalizeDisplayName(string? value, string fallback)
    {
        string normalized = NormalizeOptional(value) ?? fallback;
        if (normalized.Length > 160)
        {
            throw new ArgumentException("Value must be 160 characters or fewer.");
        }

        return normalized;
    }

    private static string NormalizeApplicationType(string? value)
        => NormalizeOptional(value) ?? "service";

    private static string? NormalizeOptional(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public static class CryptoApiAuthenticationDefaults
{
    public const string ApiKeyAuthenticationMode = "api-key";
    public const string ApiKeyCredentialType = "api-key-secret";

    public const string ApiKeyIdHeaderName = "X-Api-Key-Id";
    public const string ApiKeySecretHeaderName = "X-Api-Key-Secret";
}
