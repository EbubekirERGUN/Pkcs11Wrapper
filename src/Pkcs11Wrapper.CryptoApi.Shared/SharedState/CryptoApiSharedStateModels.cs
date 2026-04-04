namespace Pkcs11Wrapper.CryptoApi.SharedState;

public sealed record CryptoApiSharedStateStatus(
    bool Configured,
    string Provider,
    string? ConnectionTarget,
    int SchemaVersion,
    int ApiClientCount,
    int ApiClientKeyCount,
    int KeyAliasCount,
    int PolicyCount,
    int ClientPolicyBindingCount,
    int KeyAliasPolicyBindingCount,
    IReadOnlyList<string> SharedReadyAreas);

public sealed record CryptoApiSharedStateSnapshot(
    IReadOnlyList<CryptoApiClientRecord> Clients,
    IReadOnlyList<CryptoApiClientKeyRecord> ClientKeys,
    IReadOnlyList<CryptoApiKeyAliasRecord> KeyAliases,
    IReadOnlyList<CryptoApiPolicyRecord> Policies,
    IReadOnlyList<CryptoApiClientPolicyBinding> ClientPolicyBindings,
    IReadOnlyList<CryptoApiKeyAliasPolicyBinding> KeyAliasPolicyBindings);

public sealed record CryptoApiClientAuthenticationState(
    CryptoApiClientRecord Client,
    CryptoApiClientKeyRecord Key,
    IReadOnlyList<Guid> BoundPolicyIds);

public sealed record CryptoApiKeyAuthorizationState(
    CryptoApiClientRecord? Client,
    CryptoApiKeyAliasRecord? Alias,
    IReadOnlyList<CryptoApiPolicyRecord> SharedPolicies);

public sealed record CryptoApiClientRecord(
    Guid ClientId,
    string ClientName,
    string DisplayName,
    string ApplicationType,
    string AuthenticationMode,
    bool IsEnabled,
    string? Notes,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public sealed record CryptoApiClientKeyRecord(
    Guid ClientKeyId,
    Guid ClientId,
    string KeyName,
    string KeyIdentifier,
    string CredentialType,
    string SecretHashAlgorithm,
    string SecretHash,
    string? SecretHint,
    bool IsEnabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? RevokedAtUtc,
    string? RevokedReason,
    DateTimeOffset? LastUsedAtUtc);

public sealed record CryptoApiKeyAliasRecord(
    Guid AliasId,
    string AliasName,
    string? DeviceRoute,
    ulong? SlotId,
    string? ObjectLabel,
    string? ObjectIdHex,
    string? Notes,
    bool IsEnabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public sealed record CryptoApiPolicyRecord(
    Guid PolicyId,
    string PolicyName,
    string? Description,
    int Revision,
    string DocumentJson,
    bool IsEnabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public sealed record CryptoApiClientPolicyBinding(
    Guid ClientId,
    Guid PolicyId,
    DateTimeOffset BoundAtUtc);

public sealed record CryptoApiKeyAliasPolicyBinding(
    Guid AliasId,
    Guid PolicyId,
    DateTimeOffset BoundAtUtc);
