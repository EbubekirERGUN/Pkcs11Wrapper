using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;

namespace Pkcs11Wrapper.CryptoApi.Caching;

public interface ICryptoApiDistributedHotPathCache
{
    bool Enabled { get; }

    Task<long?> GetAuthStateRevisionAsync(CancellationToken cancellationToken = default);

    Task SetAuthStateRevisionAsync(long authStateRevision, CancellationToken cancellationToken = default);

    Task<CryptoApiAuthenticatedClient?> GetAuthenticatedClientAsync(
        long authStateRevision,
        string keyIdentifier,
        string secretFingerprint,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    Task SetAuthenticatedClientAsync(
        long authStateRevision,
        string keyIdentifier,
        string secretFingerprint,
        CryptoApiAuthenticatedClient authenticatedClient,
        CancellationToken cancellationToken = default);

    Task<CryptoApiAuthorizedKeyOperation?> GetAuthorizedOperationAsync(
        long authStateRevision,
        Guid clientId,
        string aliasName,
        string operation,
        CryptoApiAuthenticatedClient client,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    Task SetAuthorizedOperationAsync(
        long authStateRevision,
        Guid clientId,
        CryptoApiAuthorizedKeyOperation authorization,
        CancellationToken cancellationToken = default);

    Task<bool?> TryAcquireLastUsedRefreshLeaseAsync(
        Guid clientKeyId,
        DateTimeOffset now,
        TimeSpan minimumInterval,
        CancellationToken cancellationToken = default);
}
