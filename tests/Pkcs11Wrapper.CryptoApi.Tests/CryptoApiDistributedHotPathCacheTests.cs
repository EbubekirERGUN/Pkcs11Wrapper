using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Caching;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;
using static Pkcs11Wrapper.CryptoApi.Tests.PostgresTestEnvironment;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiDistributedHotPathCacheTests
{
    [Fact]
    public async Task DistributedHotCacheKeepsNewestAuthStateRevisionWhenOlderValueArrivesLater()
    {
        FakeDistributedHotPathCache distributedCache = new();

        await distributedCache.SetAuthStateRevisionAsync(7);
        await distributedCache.SetAuthStateRevisionAsync(5);

        long? revision = await distributedCache.GetAuthStateRevisionAsync();

        Assert.Equal(7, revision);
    }

    [PostgresFact]
    public async Task PostgresOnlyWarmInstanceInvalidatesRevokedKeyAcrossInstancesWithoutRevisionDatabaseChurn()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        ServiceSet instanceA = CreateServiceSet(scope.Options, new NoOpCryptoApiDistributedHotPathCache(), DateTimeOffset.Parse("2026-04-04T12:00:00Z"));
        ServiceSet instanceB = CreateServiceSet(scope.Options, new NoOpCryptoApiDistributedHotPathCache(), DateTimeOffset.Parse("2026-04-04T12:00:05Z"));

        SeededAccess access = await SeedAuthorizedAccessAsync(instanceA);
        instanceA.Store.ResetCounters();
        instanceB.Store.ResetCounters();

        CryptoApiRequestAuthorizationResult warm = await instanceB.Authorization.AuthorizeRequestAsync(
            access.Key.KeyIdentifier,
            access.Key.Secret,
            access.Alias.AliasName,
            "sign");

        Assert.True(warm.Succeeded, warm.FailureReason);
        Assert.Equal(1, instanceB.Store.AuthStateRevisionDatabaseReadCount);
        Assert.Equal(1, instanceB.Store.AuthenticationStateReads);
        Assert.Equal(1, instanceB.Store.AuthorizationStateReads);

        await instanceA.ClientManagement.RevokeClientKeyAsync(access.Key.ClientKeyId, "rotation");

        CryptoApiRequestAuthorizationResult afterRevocation = await WaitForAuthorizationResultAsync(
            () => instanceB.Authorization.AuthorizeRequestAsync(
                access.Key.KeyIdentifier,
                access.Key.Secret,
                access.Alias.AliasName,
                "sign"),
            result => !result.Succeeded,
            TimeSpan.FromSeconds(5));

        Assert.False(afterRevocation.Succeeded);
        Assert.Equal(401, afterRevocation.FailureStatusCode);
        Assert.Equal("API key id or secret is invalid.", afterRevocation.FailureReason);
        Assert.Equal(1, instanceB.Store.AuthStateRevisionDatabaseReadCount);
        Assert.Equal(2, instanceB.Store.AuthenticationStateReads);
        Assert.Equal(1, instanceB.Store.AuthorizationStateReads);
    }

    [PostgresFact]
    public async Task DistributedHotCacheSharesWarmAuthorizationAcrossInstances()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        FakeDistributedHotPathCache distributedCache = new();
        ServiceSet instanceA = CreateServiceSet(scope.Options, distributedCache, DateTimeOffset.Parse("2026-04-04T12:00:00Z"));
        ServiceSet instanceB = CreateServiceSet(scope.Options, distributedCache, DateTimeOffset.Parse("2026-04-04T12:00:05Z"));

        SeededAccess access = await SeedAuthorizedAccessAsync(instanceA);
        instanceA.Store.ResetCounters();
        instanceB.Store.ResetCounters();

        CryptoApiRequestAuthorizationResult first = await instanceA.Authorization.AuthorizeRequestAsync(
            access.Key.KeyIdentifier,
            access.Key.Secret,
            access.Alias.AliasName,
            "sign");

        Assert.True(first.Succeeded, first.FailureReason);
        Assert.Equal(1, instanceA.Store.AuthenticationStateReads);
        Assert.Equal(1, instanceA.Store.AuthorizationStateReads);
        Assert.Equal(1, instanceA.Store.LastUsedTouches);
        Assert.Equal(0, instanceA.Store.AuthStateRevisionReads);

        CryptoApiRequestAuthorizationResult second = await instanceB.Authorization.AuthorizeRequestAsync(
            access.Key.KeyIdentifier,
            access.Key.Secret,
            access.Alias.AliasName,
            "sign");

        Assert.True(second.Succeeded, second.FailureReason);
        Assert.Equal(0, instanceB.Store.AuthStateRevisionReads);
        Assert.Equal(0, instanceB.Store.AuthenticationStateReads);
        Assert.Equal(0, instanceB.Store.AuthorizationStateReads);
        Assert.Equal(0, instanceB.Store.LastUsedTouches);
    }

    [PostgresFact]
    public async Task DistributedHotCacheInvalidatesAcrossInstancesWhenKeyIsRevoked()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        FakeDistributedHotPathCache distributedCache = new();
        ServiceSet instanceA = CreateServiceSet(scope.Options, distributedCache, DateTimeOffset.Parse("2026-04-04T12:00:00Z"));
        ServiceSet instanceB = CreateServiceSet(scope.Options, distributedCache, DateTimeOffset.Parse("2026-04-04T12:00:05Z"));

        SeededAccess access = await SeedAuthorizedAccessAsync(instanceA);
        CryptoApiRequestAuthorizationResult warm = await instanceA.Authorization.AuthorizeRequestAsync(
            access.Key.KeyIdentifier,
            access.Key.Secret,
            access.Alias.AliasName,
            "sign");
        Assert.True(warm.Succeeded, warm.FailureReason);

        instanceB.Store.ResetCounters();
        await instanceA.ClientManagement.RevokeClientKeyAsync(access.Key.ClientKeyId, "rotation");

        CryptoApiRequestAuthorizationResult afterRevocation = await instanceB.Authorization.AuthorizeRequestAsync(
            access.Key.KeyIdentifier,
            access.Key.Secret,
            access.Alias.AliasName,
            "sign");

        Assert.False(afterRevocation.Succeeded);
        Assert.Equal(401, afterRevocation.FailureStatusCode);
        Assert.Equal("API key id or secret is invalid.", afterRevocation.FailureReason);
        Assert.Equal(0, instanceB.Store.AuthStateRevisionReads);
        Assert.Equal(1, instanceB.Store.AuthenticationStateReads);
        Assert.Equal(0, instanceB.Store.AuthorizationStateReads);
        Assert.Equal(0, instanceB.Store.LastUsedTouches);
    }

    private static ServiceSet CreateServiceSet(
        CryptoApiSharedPersistenceOptions sharedStateOptions,
        ICryptoApiDistributedHotPathCache distributedCache,
        DateTimeOffset utcNow)
    {
        CountingAuthoritativeSharedStateStore authoritativeStore = new(new PostgresCryptoApiSharedStateStore(Options.Create(sharedStateOptions)));
        ICryptoApiSharedStateStore sharedStateStore = new CryptoApiHotPathSharedStateStore(authoritativeStore, distributedCache);
        MutableTimeProvider timeProvider = new(utcNow);
        CryptoApiRequestPathCache requestPathCache = new(timeProvider, new CryptoApiRequestPathCachingOptions
        {
            Enabled = true,
            EntryTtlSeconds = 300,
            LastUsedWriteIntervalSeconds = 30
        });
        CryptoApiClientSecretGenerator generator = new();
        CryptoApiClientSecretHasher hasher = new();

        return new ServiceSet(
            Store: authoritativeStore,
            ClientManagement: new CryptoApiClientManagementService(sharedStateStore, generator, hasher, timeProvider),
            AccessManagement: new CryptoApiKeyAccessManagementService(sharedStateStore, timeProvider),
            Authorization: new CryptoApiKeyOperationAuthorizationService(sharedStateStore, distributedCache, timeProvider, hasher, requestPathCache),
            Authentication: new CryptoApiClientAuthenticationService(sharedStateStore, distributedCache, hasher, timeProvider, requestPathCache));
    }

    private static async Task<SeededAccess> SeedAuthorizedAccessAsync(ServiceSet services)
    {
        CryptoApiManagedClient client = await services.ClientManagement.CreateClientAsync(new CreateCryptoApiClientRequest(
            ClientName: $"client-{Guid.NewGuid():N}",
            DisplayName: "Gateway A",
            ApplicationType: "gateway",
            Notes: null));
        CryptoApiCreatedClientKey key = await services.ClientManagement.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(client.ClientId, "primary", null));
        CryptoApiManagedPolicy policy = await services.AccessManagement.CreatePolicyAsync(new CreateCryptoApiPolicyRequest(
            PolicyName: $"gateway-sign-{Guid.NewGuid():N}",
            Description: null,
            AllowedOperations: ["sign"]));
        CryptoApiManagedKeyAlias alias = await services.AccessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
            AliasName: "payments-signer",
            RouteGroupName: null,
            DeviceRoute: "hsm-eu-primary",
            SlotId: 7,
            ObjectLabel: "Payments signing key",
            ObjectIdHex: "A1B2C3D4",
            Notes: null));

        await services.AccessManagement.ReplaceClientPoliciesAsync(client.ClientId, [policy.PolicyId]);
        await services.AccessManagement.ReplaceKeyAliasPoliciesAsync(alias.AliasId, [policy.PolicyId]);
        return new SeededAccess(client, key, alias, policy);
    }

    private static async Task<CryptoApiRequestAuthorizationResult> WaitForAuthorizationResultAsync(
        Func<Task<CryptoApiRequestAuthorizationResult>> action,
        Func<CryptoApiRequestAuthorizationResult, bool> predicate,
        TimeSpan timeout)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.Add(timeout);
        while (DateTimeOffset.UtcNow < deadline)
        {
            CryptoApiRequestAuthorizationResult result = await action();
            if (predicate(result))
            {
                return result;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100));
        }

        CryptoApiRequestAuthorizationResult finalResult = await action();
        Assert.True(predicate(finalResult));
        return finalResult;
    }

    private sealed record ServiceSet(
        CountingAuthoritativeSharedStateStore Store,
        CryptoApiClientManagementService ClientManagement,
        CryptoApiKeyAccessManagementService AccessManagement,
        CryptoApiKeyOperationAuthorizationService Authorization,
        CryptoApiClientAuthenticationService Authentication);

    private sealed record SeededAccess(
        CryptoApiManagedClient Client,
        CryptoApiCreatedClientKey Key,
        CryptoApiManagedKeyAlias Alias,
        CryptoApiManagedPolicy Policy);

    private sealed class CountingAuthoritativeSharedStateStore(PostgresCryptoApiSharedStateStore inner) : ICryptoApiAuthoritativeSharedStateStore
    {
        public long AuthStateRevisionDatabaseReadCount => inner.AuthStateRevisionDatabaseReadCount;

        public int AuthStateRevisionReads { get; private set; }

        public int AuthenticationStateReads { get; private set; }

        public int AuthorizationStateReads { get; private set; }

        public int LastUsedTouches { get; private set; }

        public void ResetCounters()
        {
            AuthStateRevisionReads = 0;
            AuthenticationStateReads = 0;
            AuthorizationStateReads = 0;
            LastUsedTouches = 0;
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
            => inner.InitializeAsync(cancellationToken);

        public Task<CryptoApiSharedStateStatus> GetStatusAsync(CancellationToken cancellationToken = default)
            => inner.GetStatusAsync(cancellationToken);

        public async Task<long> GetAuthStateRevisionAsync(CancellationToken cancellationToken = default)
        {
            AuthStateRevisionReads++;
            return await inner.GetAuthStateRevisionAsync(cancellationToken);
        }

        public async Task<CryptoApiClientAuthenticationState?> GetClientAuthenticationStateAsync(string keyIdentifier, CancellationToken cancellationToken = default)
        {
            AuthenticationStateReads++;
            return await inner.GetClientAuthenticationStateAsync(keyIdentifier, cancellationToken);
        }

        public async Task<CryptoApiKeyAuthorizationState> GetKeyAuthorizationStateAsync(Guid clientId, string aliasName, CancellationToken cancellationToken = default)
        {
            AuthorizationStateReads++;
            return await inner.GetKeyAuthorizationStateAsync(clientId, aliasName, cancellationToken);
        }

        public Task UpsertClientAsync(CryptoApiClientRecord client, CancellationToken cancellationToken = default)
            => inner.UpsertClientAsync(client, cancellationToken);

        public Task UpsertClientKeyAsync(CryptoApiClientKeyRecord clientKey, CancellationToken cancellationToken = default)
            => inner.UpsertClientKeyAsync(clientKey, cancellationToken);

        public async Task<bool> TryTouchClientKeyLastUsedAsync(Guid clientKeyId, DateTimeOffset lastUsedAtUtc, TimeSpan minimumInterval, CancellationToken cancellationToken = default)
        {
            LastUsedTouches++;
            return await inner.TryTouchClientKeyLastUsedAsync(clientKeyId, lastUsedAtUtc, minimumInterval, cancellationToken);
        }

        public Task UpsertKeyAliasAsync(CryptoApiKeyAliasRecord keyAlias, CancellationToken cancellationToken = default)
            => inner.UpsertKeyAliasAsync(keyAlias, cancellationToken);

        public Task UpsertPolicyAsync(CryptoApiPolicyRecord policy, CancellationToken cancellationToken = default)
            => inner.UpsertPolicyAsync(policy, cancellationToken);

        public Task ReplaceClientPolicyBindingsAsync(Guid clientId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
            => inner.ReplaceClientPolicyBindingsAsync(clientId, policyIds, cancellationToken);

        public Task ReplaceKeyAliasPolicyBindingsAsync(Guid aliasId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
            => inner.ReplaceKeyAliasPolicyBindingsAsync(aliasId, policyIds, cancellationToken);

        public Task<CryptoApiSharedStateSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
            => inner.GetSnapshotAsync(cancellationToken);
    }

    private sealed class FakeDistributedHotPathCache : ICryptoApiDistributedHotPathCache
    {
        private readonly Dictionary<string, CryptoApiAuthenticatedClient> _authenticationCache = [];
        private readonly Dictionary<string, CryptoApiAuthorizedKeyOperation> _authorizationCache = [];
        private readonly Dictionary<Guid, DateTimeOffset> _lastUsedLeases = [];
        private long? _authStateRevision;
        private readonly Lock _gate = new();

        public bool Enabled => true;

        public Task<long?> GetAuthStateRevisionAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                return Task.FromResult(_authStateRevision);
            }
        }

        public Task SetAuthStateRevisionAsync(long authStateRevision, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_authStateRevision is null || authStateRevision > _authStateRevision.Value)
                {
                    _authStateRevision = authStateRevision;
                }
            }

            return Task.CompletedTask;
        }

        public Task<CryptoApiAuthenticatedClient?> GetAuthenticatedClientAsync(
            long authStateRevision,
            string keyIdentifier,
            string secretFingerprint,
            DateTimeOffset now,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string key = $"{authStateRevision}:{keyIdentifier}:{secretFingerprint}";
            lock (_gate)
            {
                if (!_authenticationCache.TryGetValue(key, out CryptoApiAuthenticatedClient? cached))
                {
                    return Task.FromResult<CryptoApiAuthenticatedClient?>(null);
                }

                if (cached.ExpiresAtUtc is DateTimeOffset expiresAtUtc && expiresAtUtc <= now)
                {
                    _authenticationCache.Remove(key);
                    return Task.FromResult<CryptoApiAuthenticatedClient?>(null);
                }

                return Task.FromResult<CryptoApiAuthenticatedClient?>(cached with { AuthenticatedAtUtc = now });
            }
        }

        public Task SetAuthenticatedClientAsync(
            long authStateRevision,
            string keyIdentifier,
            string secretFingerprint,
            CryptoApiAuthenticatedClient authenticatedClient,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                _authenticationCache[$"{authStateRevision}:{keyIdentifier}:{secretFingerprint}"] = authenticatedClient;
            }

            return Task.CompletedTask;
        }

        public Task<CryptoApiAuthorizedKeyOperation?> GetAuthorizedOperationAsync(
            long authStateRevision,
            Guid clientId,
            string aliasName,
            string operation,
            CryptoApiAuthenticatedClient client,
            DateTimeOffset now,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string key = $"{authStateRevision}:{clientId:N}:{aliasName}:{operation}";
            lock (_gate)
            {
                if (!_authorizationCache.TryGetValue(key, out CryptoApiAuthorizedKeyOperation? authorization))
                {
                    return Task.FromResult<CryptoApiAuthorizedKeyOperation?>(null);
                }

                return Task.FromResult<CryptoApiAuthorizedKeyOperation?>(authorization with
                {
                    Client = client,
                    AuthorizedAtUtc = now
                });
            }
        }

        public Task SetAuthorizedOperationAsync(
            long authStateRevision,
            Guid clientId,
            CryptoApiAuthorizedKeyOperation authorization,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                _authorizationCache[$"{authStateRevision}:{clientId:N}:{authorization.AliasName}:{authorization.Operation}"] = authorization;
            }

            return Task.CompletedTask;
        }

        public Task<bool?> TryAcquireLastUsedRefreshLeaseAsync(
            Guid clientKeyId,
            DateTimeOffset now,
            TimeSpan minimumInterval,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_lastUsedLeases.TryGetValue(clientKeyId, out DateTimeOffset expiresAtUtc) && expiresAtUtc > now)
                {
                    return Task.FromResult<bool?>(false);
                }

                _lastUsedLeases[clientKeyId] = now.Add(minimumInterval);
                return Task.FromResult<bool?>(true);
            }
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset initialUtcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = initialUtcNow;

        public override DateTimeOffset GetUtcNow()
            => _utcNow;

        public void Advance(TimeSpan delta)
            => _utcNow = _utcNow.Add(delta);
    }
}
