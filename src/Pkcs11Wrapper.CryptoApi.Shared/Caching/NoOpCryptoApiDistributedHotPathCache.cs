using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;

namespace Pkcs11Wrapper.CryptoApi.Caching;

public sealed class NoOpCryptoApiDistributedHotPathCache : ICryptoApiDistributedHotPathCache
{
    public bool Enabled => false;

    public Task<long?> GetAuthStateRevisionAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<long?>(null);

    public Task SetAuthStateRevisionAsync(long authStateRevision, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<CryptoApiAuthenticatedClient?> GetAuthenticatedClientAsync(
        long authStateRevision,
        string keyIdentifier,
        string secretFingerprint,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
        => Task.FromResult<CryptoApiAuthenticatedClient?>(null);

    public Task SetAuthenticatedClientAsync(
        long authStateRevision,
        string keyIdentifier,
        string secretFingerprint,
        CryptoApiAuthenticatedClient authenticatedClient,
        CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<CryptoApiAuthorizedKeyOperation?> GetAuthorizedOperationAsync(
        long authStateRevision,
        Guid clientId,
        string aliasName,
        string operation,
        CryptoApiAuthenticatedClient client,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
        => Task.FromResult<CryptoApiAuthorizedKeyOperation?>(null);

    public Task SetAuthorizedOperationAsync(
        long authStateRevision,
        Guid clientId,
        CryptoApiAuthorizedKeyOperation authorization,
        CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<bool?> TryAcquireLastUsedRefreshLeaseAsync(
        Guid clientKeyId,
        DateTimeOffset now,
        TimeSpan minimumInterval,
        CancellationToken cancellationToken = default)
        => Task.FromResult<bool?>(null);
}
