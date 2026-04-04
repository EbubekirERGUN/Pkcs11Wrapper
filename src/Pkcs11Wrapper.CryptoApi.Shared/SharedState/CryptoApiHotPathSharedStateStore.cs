using Pkcs11Wrapper.CryptoApi.Caching;

namespace Pkcs11Wrapper.CryptoApi.SharedState;

public sealed class CryptoApiHotPathSharedStateStore(
    ICryptoApiAuthoritativeSharedStateStore inner,
    ICryptoApiDistributedHotPathCache distributedHotPathCache) : ICryptoApiSharedStateStore
{
    public Task InitializeAsync(CancellationToken cancellationToken = default)
        => inner.InitializeAsync(cancellationToken);

    public Task<CryptoApiSharedStateStatus> GetStatusAsync(CancellationToken cancellationToken = default)
        => inner.GetStatusAsync(cancellationToken);

    public async Task<long> GetAuthStateRevisionAsync(CancellationToken cancellationToken = default)
    {
        long? cachedRevision = await distributedHotPathCache.GetAuthStateRevisionAsync(cancellationToken);
        if (cachedRevision is > 0)
        {
            return cachedRevision.Value;
        }

        long authStateRevision = await inner.GetAuthStateRevisionAsync(cancellationToken);
        if (authStateRevision > 0)
        {
            await distributedHotPathCache.SetAuthStateRevisionAsync(authStateRevision, cancellationToken);
        }

        return authStateRevision;
    }

    public Task<CryptoApiClientAuthenticationState?> GetClientAuthenticationStateAsync(string keyIdentifier, CancellationToken cancellationToken = default)
        => inner.GetClientAuthenticationStateAsync(keyIdentifier, cancellationToken);

    public Task<CryptoApiKeyAuthorizationState> GetKeyAuthorizationStateAsync(Guid clientId, string aliasName, CancellationToken cancellationToken = default)
        => inner.GetKeyAuthorizationStateAsync(clientId, aliasName, cancellationToken);

    public async Task UpsertClientAsync(CryptoApiClientRecord client, CancellationToken cancellationToken = default)
    {
        await inner.UpsertClientAsync(client, cancellationToken);
        await RefreshAuthStateRevisionAsync(cancellationToken);
    }

    public async Task UpsertClientKeyAsync(CryptoApiClientKeyRecord clientKey, CancellationToken cancellationToken = default)
    {
        await inner.UpsertClientKeyAsync(clientKey, cancellationToken);
        await RefreshAuthStateRevisionAsync(cancellationToken);
    }

    public Task<bool> TryTouchClientKeyLastUsedAsync(Guid clientKeyId, DateTimeOffset lastUsedAtUtc, TimeSpan minimumInterval, CancellationToken cancellationToken = default)
        => inner.TryTouchClientKeyLastUsedAsync(clientKeyId, lastUsedAtUtc, minimumInterval, cancellationToken);

    public async Task UpsertKeyAliasAsync(CryptoApiKeyAliasRecord keyAlias, CancellationToken cancellationToken = default)
    {
        await inner.UpsertKeyAliasAsync(keyAlias, cancellationToken);
        await RefreshAuthStateRevisionAsync(cancellationToken);
    }

    public async Task UpsertPolicyAsync(CryptoApiPolicyRecord policy, CancellationToken cancellationToken = default)
    {
        await inner.UpsertPolicyAsync(policy, cancellationToken);
        await RefreshAuthStateRevisionAsync(cancellationToken);
    }

    public async Task ReplaceClientPolicyBindingsAsync(Guid clientId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
    {
        await inner.ReplaceClientPolicyBindingsAsync(clientId, policyIds, cancellationToken);
        await RefreshAuthStateRevisionAsync(cancellationToken);
    }

    public async Task ReplaceKeyAliasPolicyBindingsAsync(Guid aliasId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
    {
        await inner.ReplaceKeyAliasPolicyBindingsAsync(aliasId, policyIds, cancellationToken);
        await RefreshAuthStateRevisionAsync(cancellationToken);
    }

    public Task<CryptoApiSharedStateSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
        => inner.GetSnapshotAsync(cancellationToken);

    private async Task RefreshAuthStateRevisionAsync(CancellationToken cancellationToken)
    {
        if (!distributedHotPathCache.Enabled)
        {
            return;
        }

        long authStateRevision = await inner.GetAuthStateRevisionAsync(cancellationToken);
        if (authStateRevision > 0)
        {
            await distributedHotPathCache.SetAuthStateRevisionAsync(authStateRevision, cancellationToken);
        }
    }
}
