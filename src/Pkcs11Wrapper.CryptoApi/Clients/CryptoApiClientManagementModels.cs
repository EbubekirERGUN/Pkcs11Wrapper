namespace Pkcs11Wrapper.CryptoApi.Clients;

public sealed record CryptoApiClientManagementSnapshot(
    bool SharedPersistenceConfigured,
    string SharedPersistenceProvider,
    string? ConnectionTarget,
    int SchemaVersion,
    IReadOnlyList<CryptoApiManagedClient> Clients);

public sealed record CryptoApiManagedClient(
    Guid ClientId,
    string ClientName,
    string DisplayName,
    string ApplicationType,
    string AuthenticationMode,
    bool IsEnabled,
    string? Notes,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<Guid> BoundPolicyIds,
    IReadOnlyList<CryptoApiManagedClientKey> Keys);

public sealed record CryptoApiManagedClientKey(
    Guid ClientKeyId,
    Guid ClientId,
    string KeyName,
    string KeyIdentifier,
    string CredentialType,
    string SecretHashAlgorithm,
    string? SecretHint,
    bool IsEnabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? RevokedAtUtc,
    string? RevokedReason,
    DateTimeOffset? LastUsedAtUtc);

public sealed record CreateCryptoApiClientRequest(
    string ClientName,
    string DisplayName,
    string? ApplicationType,
    string? Notes);

public sealed record CreateCryptoApiClientKeyRequest(
    Guid ClientId,
    string KeyName,
    DateTimeOffset? ExpiresAtUtc);

public sealed record CryptoApiCreatedClientKey(
    Guid ClientKeyId,
    Guid ClientId,
    string KeyName,
    string KeyIdentifier,
    string Secret,
    string? SecretHint,
    string SecretHashAlgorithm,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc);

public sealed record CryptoApiAuthenticatedClient(
    Guid ClientId,
    string ClientName,
    string DisplayName,
    string ApplicationType,
    string AuthenticationMode,
    Guid ClientKeyId,
    string KeyIdentifier,
    string CredentialType,
    DateTimeOffset AuthenticatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    IReadOnlyList<Guid> BoundPolicyIds);

public sealed record CryptoApiClientAuthenticationResult(
    bool Succeeded,
    string? FailureReason,
    CryptoApiAuthenticatedClient? Client);
