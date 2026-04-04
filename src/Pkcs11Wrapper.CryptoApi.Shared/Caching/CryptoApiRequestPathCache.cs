using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;

namespace Pkcs11Wrapper.CryptoApi.Caching;

public sealed class CryptoApiRequestPathCache : IDisposable
{
    private readonly CryptoApiRequestPathCachingOptions _options;
    private readonly MemoryCache _authenticationCache;
    private readonly MemoryCache _authorizationCache;

    public CryptoApiRequestPathCache(TimeProvider timeProvider)
        : this(timeProvider, new CryptoApiRequestPathCachingOptions())
    {
    }

    public CryptoApiRequestPathCache(TimeProvider timeProvider, CryptoApiRequestPathCachingOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _authenticationCache = new MemoryCache(new MemoryCacheOptions { SizeLimit = Math.Max(1, options.AuthenticationEntryLimit) });
        _authorizationCache = new MemoryCache(new MemoryCacheOptions { SizeLimit = Math.Max(1, options.AuthorizationEntryLimit) });
    }

    public bool Enabled
        => _options.Enabled;

    public TimeSpan LastUsedWriteInterval
        => _options.LastUsedWriteInterval;

    public string CreateSecretFingerprint(string normalizedSecret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedSecret);

        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalizedSecret));
        return Convert.ToHexString(hash);
    }

    public bool TryGetAuthenticatedClient(long authStateRevision, string keyIdentifier, string secretFingerprint, DateTimeOffset now, out CryptoApiAuthenticatedClient authenticatedClient)
    {
        authenticatedClient = null!;

        if (!Enabled)
        {
            return false;
        }

        if (!_authenticationCache.TryGetValue(new AuthenticationCacheKey(authStateRevision, keyIdentifier, secretFingerprint), out AuthenticationCacheEntry? entry)
            || entry is null)
        {
            return false;
        }

        if (entry.Template.ExpiresAtUtc is DateTimeOffset expiresAtUtc && expiresAtUtc <= now)
        {
            return false;
        }

        authenticatedClient = entry.Template with { AuthenticatedAtUtc = now };
        return true;
    }

    public void SetAuthenticatedClient(long authStateRevision, string keyIdentifier, string secretFingerprint, CryptoApiAuthenticatedClient authenticatedClient, DateTimeOffset lastUsedRecordedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(authenticatedClient);

        if (!Enabled)
        {
            return;
        }

        _authenticationCache.Set(
            new AuthenticationCacheKey(authStateRevision, keyIdentifier, secretFingerprint),
            new AuthenticationCacheEntry(authenticatedClient, lastUsedRecordedAtUtc),
            new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _options.EntryTtl,
                Size = 1
            });
    }

    public bool ShouldRefreshLastUsed(long authStateRevision, string keyIdentifier, string secretFingerprint, DateTimeOffset now)
    {
        if (!Enabled)
        {
            return true;
        }

        if (!_authenticationCache.TryGetValue(new AuthenticationCacheKey(authStateRevision, keyIdentifier, secretFingerprint), out AuthenticationCacheEntry? entry)
            || entry is null)
        {
            return true;
        }

        return now - entry.LastUsedRecordedAtUtc >= _options.LastUsedWriteInterval;
    }

    public void RecordLastUsedRefresh(long authStateRevision, string keyIdentifier, string secretFingerprint, DateTimeOffset now)
    {
        if (!Enabled)
        {
            return;
        }

        AuthenticationCacheKey cacheKey = new(authStateRevision, keyIdentifier, secretFingerprint);
        if (_authenticationCache.TryGetValue(cacheKey, out AuthenticationCacheEntry? entry)
            && entry is not null)
        {
            _authenticationCache.Set(
                cacheKey,
                entry with { LastUsedRecordedAtUtc = now },
                new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = _options.EntryTtl,
                    Size = 1
                });
        }
    }

    public bool TryGetAuthorizedOperation(long authStateRevision, Guid clientId, string aliasName, string operation, CryptoApiAuthenticatedClient client, DateTimeOffset now, out CryptoApiAuthorizedKeyOperation authorization)
    {
        authorization = null!;

        if (!Enabled)
        {
            return false;
        }

        if (!_authorizationCache.TryGetValue(new AuthorizationCacheKey(authStateRevision, clientId, aliasName, operation), out AuthorizationCacheEntry? entry)
            || entry is null)
        {
            return false;
        }

        authorization = new CryptoApiAuthorizedKeyOperation(
            Client: client,
            Operation: entry.Operation,
            AliasId: entry.AliasId,
            AliasName: entry.AliasName,
            RoutePlan: entry.RoutePlan,
            MatchedPolicies: entry.MatchedPolicies,
            AuthorizedAtUtc: now);
        return true;
    }

    public void SetAuthorizedOperation(long authStateRevision, Guid clientId, CryptoApiAuthorizedKeyOperation authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        if (!Enabled)
        {
            return;
        }

        _authorizationCache.Set(
            new AuthorizationCacheKey(authStateRevision, clientId, authorization.AliasName, authorization.Operation),
            new AuthorizationCacheEntry(
                authorization.Operation,
                authorization.AliasId,
                authorization.AliasName,
                authorization.RoutePlan,
                authorization.MatchedPolicies),
            new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _options.EntryTtl,
                Size = 1
            });
    }

    public void Dispose()
    {
        _authenticationCache.Dispose();
        _authorizationCache.Dispose();
    }

    private sealed record AuthenticationCacheKey(long AuthStateRevision, string KeyIdentifier, string SecretFingerprint);

    private sealed record AuthenticationCacheEntry(
        CryptoApiAuthenticatedClient Template,
        DateTimeOffset LastUsedRecordedAtUtc);

    private sealed record AuthorizationCacheKey(long AuthStateRevision, Guid ClientId, string AliasName, string Operation);

    private sealed record AuthorizationCacheEntry(
        string Operation,
        Guid AliasId,
        string AliasName,
        CryptoApiRoutePlan RoutePlan,
        IReadOnlyList<CryptoApiMatchedPolicy> MatchedPolicies);
}
