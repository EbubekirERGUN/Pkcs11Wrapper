namespace Pkcs11Wrapper.CryptoApi.SharedState;

public interface ICryptoApiSharedStateStore
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    Task<CryptoApiSharedStateStatus> GetStatusAsync(CancellationToken cancellationToken = default);

    Task UpsertClientAsync(CryptoApiClientRecord client, CancellationToken cancellationToken = default);

    Task UpsertClientKeyAsync(CryptoApiClientKeyRecord clientKey, CancellationToken cancellationToken = default);

    Task UpsertKeyAliasAsync(CryptoApiKeyAliasRecord keyAlias, CancellationToken cancellationToken = default);

    Task UpsertPolicyAsync(CryptoApiPolicyRecord policy, CancellationToken cancellationToken = default);

    Task ReplaceClientPolicyBindingsAsync(Guid clientId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default);

    Task ReplaceKeyAliasPolicyBindingsAsync(Guid aliasId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default);

    Task<CryptoApiSharedStateSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default);
}
