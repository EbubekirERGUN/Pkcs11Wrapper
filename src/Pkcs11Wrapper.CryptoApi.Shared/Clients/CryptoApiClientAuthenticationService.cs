using Pkcs11Wrapper.CryptoApi.Caching;
using Pkcs11Wrapper.CryptoApi.Observability;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Clients;

public sealed class CryptoApiClientAuthenticationService
{
    private readonly ICryptoApiSharedStateStore _sharedStateStore;
    private readonly ICryptoApiDistributedHotPathCache _distributedHotPathCache;
    private readonly CryptoApiClientSecretHasher _secretHasher;
    private readonly TimeProvider _timeProvider;
    private readonly CryptoApiRequestPathCache _requestPathCache;
    private readonly CryptoApiMetrics? _metrics;

    public CryptoApiClientAuthenticationService(
        ICryptoApiSharedStateStore sharedStateStore,
        ICryptoApiDistributedHotPathCache distributedHotPathCache,
        CryptoApiClientSecretHasher secretHasher,
        TimeProvider timeProvider,
        CryptoApiRequestPathCache? requestPathCache = null,
        CryptoApiMetrics? metrics = null)
    {
        _sharedStateStore = sharedStateStore;
        _distributedHotPathCache = distributedHotPathCache;
        _secretHasher = secretHasher;
        _timeProvider = timeProvider;
        _requestPathCache = requestPathCache ?? new CryptoApiRequestPathCache(timeProvider);
        _metrics = metrics;
    }

    public async Task<CryptoApiClientAuthenticationResult> AuthenticateAsync(string? keyIdentifier, string? secret, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyIdentifier) || string.IsNullOrWhiteSpace(secret))
        {
            _metrics?.RecordAuthenticationResult("missing_credentials", "input_validation");
            return Failed("API key id and secret are required.");
        }

        string normalizedKeyIdentifier = keyIdentifier.Trim();
        string normalizedSecret = secret.Trim();

        long authStateRevision = await _sharedStateStore.GetAuthStateRevisionAsync(cancellationToken);
        if (authStateRevision <= 0)
        {
            _metrics?.RecordAuthenticationResult("shared_state_unconfigured", "shared_state");
            return Failed("Shared persistence is not configured.");
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        string secretFingerprint = _requestPathCache.CreateSecretFingerprint(normalizedSecret);
        bool cacheEnabled = _requestPathCache.Enabled;
        if (!cacheEnabled)
        {
            _metrics?.RecordRequestPathCacheLookup("authentication", "memory", "disabled");
        }

        if (_requestPathCache.TryGetAuthenticatedClient(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now, out CryptoApiAuthenticatedClient cachedClient))
        {
            _metrics?.RecordRequestPathCacheLookup("authentication", "memory", "hit");
            await RefreshLastUsedIfNeededAsync(authStateRevision, cachedClient.ClientKeyId, normalizedKeyIdentifier, secretFingerprint, now, cancellationToken);
            _metrics?.RecordAuthenticationResult("success", "memory_cache");
            return new CryptoApiClientAuthenticationResult(
                Succeeded: true,
                FailureReason: null,
                Client: cachedClient);
        }

        if (cacheEnabled)
        {
            _metrics?.RecordRequestPathCacheLookup("authentication", "memory", "miss");
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
            _metrics?.RecordAuthenticationResult("success", "redis_cache");
            return new CryptoApiClientAuthenticationResult(
                Succeeded: true,
                FailureReason: null,
                Client: distributedClient);
        }

        CryptoApiClientAuthenticationState? authenticationState = await _sharedStateStore.GetClientAuthenticationStateAsync(normalizedKeyIdentifier, cancellationToken);
        if (authenticationState is null)
        {
            _metrics?.RecordAuthenticationResult("key_not_found", "shared_state");
            return Failed("API key was not found.");
        }

        CryptoApiClientRecord client = authenticationState.Client;
        CryptoApiClientKeyRecord key = authenticationState.Key;

        if (!client.IsEnabled)
        {
            _metrics?.RecordAuthenticationResult("client_disabled", "shared_state");
            return Failed("API client is disabled.");
        }

        if (key.RevokedAtUtc is not null)
        {
            _metrics?.RecordAuthenticationResult("key_revoked", "shared_state");
            return Failed("API key has been revoked.");
        }

        if (!key.IsEnabled)
        {
            _metrics?.RecordAuthenticationResult("key_disabled", "shared_state");
            return Failed("API key is disabled.");
        }

        if (key.ExpiresAtUtc is DateTimeOffset expiresAtUtc && expiresAtUtc <= now)
        {
            _metrics?.RecordAuthenticationResult("key_expired", "shared_state");
            return Failed("API key has expired.");
        }

        if (!_secretHasher.VerifySecret(normalizedSecret, key.SecretHash))
        {
            _metrics?.RecordAuthenticationResult("secret_invalid", "shared_state");
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
        _metrics?.RecordAuthenticationResult("success", "shared_state");

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
            _metrics?.RecordLastUsedRefreshEvent("authentication", "decision", "not_needed");
            return;
        }

        if (_distributedHotPathCache.Enabled)
        {
            bool? leaseAcquired = await _distributedHotPathCache.TryAcquireLastUsedRefreshLeaseAsync(clientKeyId, now, minimumInterval, cancellationToken);
            if (leaseAcquired is false)
            {
                _requestPathCache.RecordLastUsedRefresh(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now);
                _metrics?.RecordLastUsedRefreshEvent("authentication", "lease", "denied");
                return;
            }

            _metrics?.RecordLastUsedRefreshEvent("authentication", "lease", leaseAcquired is true ? "acquired" : "unavailable");
        }

        bool updated = await _sharedStateStore.TryTouchClientKeyLastUsedAsync(clientKeyId, now, minimumInterval, cancellationToken);
        _metrics?.RecordLastUsedRefreshEvent("authentication", "shared_state", updated ? "applied" : "skipped");
        _requestPathCache.RecordLastUsedRefresh(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now);
    }
    private static CryptoApiClientAuthenticationResult Failed(string reason)
        => new(
            Succeeded: false,
            FailureReason: reason,
            Client: null);
}
