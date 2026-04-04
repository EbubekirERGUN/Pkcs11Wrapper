using Pkcs11Wrapper.CryptoApi.Caching;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Clients;

public sealed class CryptoApiClientAuthenticationService
{
    private readonly ICryptoApiSharedStateStore _sharedStateStore;
    private readonly ICryptoApiDistributedHotPathCache _distributedHotPathCache;
    private readonly CryptoApiClientSecretHasher _secretHasher;
    private readonly TimeProvider _timeProvider;
    private readonly CryptoApiRequestPathCache _requestPathCache;

    public CryptoApiClientAuthenticationService(
        ICryptoApiSharedStateStore sharedStateStore,
        ICryptoApiDistributedHotPathCache distributedHotPathCache,
        CryptoApiClientSecretHasher secretHasher,
        TimeProvider timeProvider,
        CryptoApiRequestPathCache? requestPathCache = null)
    {
        _sharedStateStore = sharedStateStore;
        _distributedHotPathCache = distributedHotPathCache;
        _secretHasher = secretHasher;
        _timeProvider = timeProvider;
        _requestPathCache = requestPathCache ?? new CryptoApiRequestPathCache(timeProvider);
    }

    public async Task<CryptoApiClientAuthenticationResult> AuthenticateAsync(string? keyIdentifier, string? secret, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyIdentifier) || string.IsNullOrWhiteSpace(secret))
        {
            return Failed("API key id and secret are required.");
        }

        string normalizedKeyIdentifier = keyIdentifier.Trim();
        string normalizedSecret = secret.Trim();

        long authStateRevision = await _sharedStateStore.GetAuthStateRevisionAsync(cancellationToken);
        if (authStateRevision <= 0)
        {
            return Failed("Shared persistence is not configured.");
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        string secretFingerprint = _requestPathCache.CreateSecretFingerprint(normalizedSecret);
        if (_requestPathCache.TryGetAuthenticatedClient(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now, out CryptoApiAuthenticatedClient cachedClient))
        {
            await RefreshLastUsedIfNeededAsync(authStateRevision, cachedClient.ClientKeyId, normalizedKeyIdentifier, secretFingerprint, now, cancellationToken);
            return new CryptoApiClientAuthenticationResult(
                Succeeded: true,
                FailureReason: null,
                Client: cachedClient);
        }

        CryptoApiAuthenticatedClient? distributedClient = await _distributedHotPathCache.GetAuthenticatedClientAsync(
            authStateRevision,
            normalizedKeyIdentifier,
            secretFingerprint,
            now,
            cancellationToken);
        if (distributedClient is not null)
        {
            _requestPathCache.SetAuthenticatedClient(authStateRevision, normalizedKeyIdentifier, secretFingerprint, distributedClient, now);
            await RefreshLastUsedIfNeededAsync(authStateRevision, distributedClient.ClientKeyId, normalizedKeyIdentifier, secretFingerprint, now, cancellationToken);
            return new CryptoApiClientAuthenticationResult(
                Succeeded: true,
                FailureReason: null,
                Client: distributedClient);
        }

        CryptoApiClientAuthenticationState? authenticationState = await _sharedStateStore.GetClientAuthenticationStateAsync(normalizedKeyIdentifier, cancellationToken);
        if (authenticationState is null)
        {
            return Failed("API key was not found.");
        }

        CryptoApiClientRecord client = authenticationState.Client;
        CryptoApiClientKeyRecord key = authenticationState.Key;

        if (!client.IsEnabled)
        {
            return Failed("API client is disabled.");
        }

        if (key.RevokedAtUtc is not null)
        {
            return Failed("API key has been revoked.");
        }

        if (!key.IsEnabled)
        {
            return Failed("API key is disabled.");
        }

        if (key.ExpiresAtUtc is DateTimeOffset expiresAtUtc && expiresAtUtc <= now)
        {
            return Failed("API key has expired.");
        }

        if (!_secretHasher.VerifySecret(normalizedSecret, key.SecretHash))
        {
            return Failed("API key secret is invalid.");
        }

        await RefreshLastUsedIfNeededAsync(authStateRevision, key.ClientKeyId, normalizedKeyIdentifier, secretFingerprint, now, key.LastUsedAtUtc, cancellationToken);

        CryptoApiAuthenticatedClient authenticatedClient = new(
            ClientId: client.ClientId,
            ClientName: client.ClientName,
            DisplayName: client.DisplayName,
            ApplicationType: client.ApplicationType,
            AuthenticationMode: client.AuthenticationMode,
            ClientKeyId: key.ClientKeyId,
            KeyIdentifier: key.KeyIdentifier,
            CredentialType: key.CredentialType,
            AuthenticatedAtUtc: now,
            ExpiresAtUtc: key.ExpiresAtUtc,
            BoundPolicyIds: authenticationState.BoundPolicyIds);

        _requestPathCache.SetAuthenticatedClient(authStateRevision, normalizedKeyIdentifier, secretFingerprint, authenticatedClient, now);
        await _distributedHotPathCache.SetAuthenticatedClientAsync(authStateRevision, normalizedKeyIdentifier, secretFingerprint, authenticatedClient, cancellationToken);

        return new CryptoApiClientAuthenticationResult(
            Succeeded: true,
            FailureReason: null,
            Client: authenticatedClient);
    }

    private async Task RefreshLastUsedIfNeededAsync(
        long authStateRevision,
        Guid clientKeyId,
        string normalizedKeyIdentifier,
        string secretFingerprint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
        => await RefreshLastUsedIfNeededAsync(authStateRevision, clientKeyId, normalizedKeyIdentifier, secretFingerprint, now, null, cancellationToken);

    private async Task RefreshLastUsedIfNeededAsync(
        long authStateRevision,
        Guid clientKeyId,
        string normalizedKeyIdentifier,
        string secretFingerprint,
        DateTimeOffset now,
        DateTimeOffset? currentLastUsedAtUtc,
        CancellationToken cancellationToken)
    {
        TimeSpan minimumInterval = _requestPathCache.LastUsedWriteInterval;
        bool shouldRefresh = currentLastUsedAtUtc is DateTimeOffset lastUsedAtUtc
            ? now - lastUsedAtUtc >= minimumInterval
            : _requestPathCache.ShouldRefreshLastUsed(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now);

        if (!shouldRefresh)
        {
            return;
        }

        if (_distributedHotPathCache.Enabled)
        {
            bool? leaseAcquired = await _distributedHotPathCache.TryAcquireLastUsedRefreshLeaseAsync(clientKeyId, now, minimumInterval, cancellationToken);
            if (leaseAcquired is false)
            {
                _requestPathCache.RecordLastUsedRefresh(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now);
                return;
            }
        }

        _ = await _sharedStateStore.TryTouchClientKeyLastUsedAsync(clientKeyId, now, minimumInterval, cancellationToken);
        _requestPathCache.RecordLastUsedRefresh(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now);
    }
    private static CryptoApiClientAuthenticationResult Failed(string reason)
        => new(
            Succeeded: false,
            FailureReason: reason,
            Client: null);
}
