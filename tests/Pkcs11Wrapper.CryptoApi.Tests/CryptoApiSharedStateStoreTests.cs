using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiSharedStateStoreTests
{
    [Fact]
    public async Task SharedStateStoreSharesStateAcrossIndependentInstances()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-{Guid.NewGuid():N}.db");
        try
        {
            CryptoApiSharedPersistenceOptions options = new()
            {
                Provider = "Sqlite",
                ConnectionString = $"Data Source={databasePath}",
                AutoInitialize = true
            };

            ICryptoApiSharedStateStore writer = new SqliteCryptoApiSharedStateStore(Options.Create(options));
            Guid clientId = Guid.NewGuid();
            Guid clientKeyId = Guid.NewGuid();
            Guid aliasId = Guid.NewGuid();
            Guid policyId = Guid.NewGuid();
            DateTimeOffset now = DateTimeOffset.UtcNow;

            await writer.UpsertClientAsync(new CryptoApiClientRecord(
                clientId,
                "ingress-gateway",
                "Ingress Gateway",
                "gateway",
                "api-key",
                true,
                "Primary calling service",
                now,
                now));
            await writer.UpsertClientKeyAsync(new CryptoApiClientKeyRecord(
                clientKeyId,
                clientId,
                "primary-hmac",
                "kid-ingress-primary",
                "api-key-secret",
                "pbkdf2-sha256-v1",
                "pbkdf2-sha256-v1$100000$salt$hash",
                "ing...mary",
                true,
                now,
                now,
                null,
                null,
                null,
                null));
            await writer.UpsertPolicyAsync(new CryptoApiPolicyRecord(
                policyId,
                "signing-default",
                "Default sign policy",
                1,
                "{\"version\":1,\"allowedOperations\":[\"sign\"]}",
                true,
                now,
                now));
            await writer.UpsertKeyAliasAsync(new CryptoApiKeyAliasRecord(
                aliasId,
                "payments-signer",
                "hsm-eu-primary",
                7,
                "Payments signing key",
                "A1B2C3D4",
                "Resolves the default outbound signing key.",
                true,
                now,
                now));
            await writer.ReplaceClientPolicyBindingsAsync(clientId, [policyId]);
            await writer.ReplaceKeyAliasPolicyBindingsAsync(aliasId, [policyId]);

            ICryptoApiSharedStateStore reader = new SqliteCryptoApiSharedStateStore(Options.Create(options));
            CryptoApiSharedStateStatus status = await reader.GetStatusAsync();
            CryptoApiSharedStateSnapshot snapshot = await reader.GetSnapshotAsync();

            Assert.True(status.Configured);
            Assert.Equal(CryptoApiSharedStateConstants.SchemaVersion, status.SchemaVersion);
            Assert.Equal(1, status.ApiClientCount);
            Assert.Equal(1, status.ApiClientKeyCount);
            Assert.Equal(1, status.KeyAliasCount);
            Assert.Equal(1, status.PolicyCount);
            Assert.Equal(1, status.ClientPolicyBindingCount);
            Assert.Equal(1, status.KeyAliasPolicyBindingCount);
            Assert.Equal(databasePath, status.ConnectionTarget);

            CryptoApiClientRecord client = Assert.Single(snapshot.Clients);
            Assert.Equal("ingress-gateway", client.ClientName);
            Assert.Equal("gateway", client.ApplicationType);
            Assert.Equal("api-key", client.AuthenticationMode);

            CryptoApiClientKeyRecord clientKey = Assert.Single(snapshot.ClientKeys);
            Assert.Equal(clientId, clientKey.ClientId);
            Assert.Equal("kid-ingress-primary", clientKey.KeyIdentifier);
            Assert.Equal("pbkdf2-sha256-v1", clientKey.SecretHashAlgorithm);
            Assert.Equal("pbkdf2-sha256-v1$100000$salt$hash", clientKey.SecretHash);
            Assert.Null(clientKey.RevokedAtUtc);
            Assert.Null(clientKey.LastUsedAtUtc);

            CryptoApiKeyAliasRecord alias = Assert.Single(snapshot.KeyAliases);
            Assert.Equal("hsm-eu-primary", alias.DeviceRoute);
            Assert.Equal((ulong)7, alias.SlotId);
            Assert.Equal("Payments signing key", alias.ObjectLabel);

            CryptoApiPolicyRecord policy = Assert.Single(snapshot.Policies);
            Assert.Equal("signing-default", policy.PolicyName);
            Assert.Contains("allowedOperations", policy.DocumentJson, StringComparison.Ordinal);

            CryptoApiClientPolicyBinding clientBinding = Assert.Single(snapshot.ClientPolicyBindings);
            Assert.Equal(clientId, clientBinding.ClientId);
            Assert.Equal(policyId, clientBinding.PolicyId);

            CryptoApiKeyAliasPolicyBinding aliasBinding = Assert.Single(snapshot.KeyAliasPolicyBindings);
            Assert.Equal(aliasId, aliasBinding.AliasId);
            Assert.Equal(policyId, aliasBinding.PolicyId);
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    [Fact]
    public async Task AuthStateRevisionTracksSemanticChangesButNotLastUsedTouches()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-revision-{Guid.NewGuid():N}.db");
        try
        {
            CryptoApiSharedPersistenceOptions options = new()
            {
                Provider = "Sqlite",
                ConnectionString = $"Data Source={databasePath}",
                AutoInitialize = true
            };

            ICryptoApiSharedStateStore store = new SqliteCryptoApiSharedStateStore(Options.Create(options));
            DateTimeOffset now = DateTimeOffset.UtcNow;
            Guid clientId = Guid.NewGuid();
            Guid clientKeyId = Guid.NewGuid();

            long initialRevision = await store.GetAuthStateRevisionAsync();
            await store.UpsertClientAsync(new CryptoApiClientRecord(
                clientId,
                "throughput-client",
                "Throughput Client",
                "gateway",
                "api-key",
                true,
                null,
                now,
                now));
            long afterClientUpsert = await store.GetAuthStateRevisionAsync();

            await store.UpsertClientKeyAsync(new CryptoApiClientKeyRecord(
                clientKeyId,
                clientId,
                "primary",
                "kid-throughput-primary",
                "api-key-secret",
                "pbkdf2-sha256-v1",
                "pbkdf2-sha256-v1$100000$salt$hash",
                "thr...ary",
                true,
                now,
                now,
                null,
                null,
                null,
                null));
            long afterKeyUpsert = await store.GetAuthStateRevisionAsync();

            bool firstTouchUpdated = await store.TryTouchClientKeyLastUsedAsync(clientKeyId, now.AddSeconds(5), TimeSpan.FromSeconds(30));
            long afterFirstTouch = await store.GetAuthStateRevisionAsync();
            bool secondTouchUpdated = await store.TryTouchClientKeyLastUsedAsync(clientKeyId, now.AddSeconds(10), TimeSpan.FromSeconds(30));
            long afterSecondTouch = await store.GetAuthStateRevisionAsync();

            Assert.True(afterClientUpsert > initialRevision);
            Assert.True(afterKeyUpsert > afterClientUpsert);
            Assert.True(firstTouchUpdated);
            Assert.False(secondTouchUpdated);
            Assert.Equal(afterKeyUpsert, afterFirstTouch);
            Assert.Equal(afterFirstTouch, afterSecondTouch);

            CryptoApiClientKeyRecord key = Assert.Single((await store.GetSnapshotAsync()).ClientKeys);
            Assert.Equal(now.AddSeconds(5).UtcDateTime, key.LastUsedAtUtc!.Value.UtcDateTime);
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    [Fact]
    public async Task ClientAuthenticationStateQueryReturnsJoinedClientKeyAndBoundPolicies()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-auth-state-{Guid.NewGuid():N}.db");
        try
        {
            CryptoApiSharedPersistenceOptions options = new()
            {
                Provider = "Sqlite",
                ConnectionString = $"Data Source={databasePath}",
                AutoInitialize = true
            };

            SqliteCryptoApiSharedStateStore store = new(Options.Create(options));
            DateTimeOffset now = DateTimeOffset.UtcNow;
            Guid clientId = Guid.NewGuid();
            Guid clientKeyId = Guid.NewGuid();
            Guid boundPolicyId = Guid.NewGuid();
            Guid unboundPolicyId = Guid.NewGuid();

            await store.UpsertClientAsync(new CryptoApiClientRecord(
                clientId,
                "targeted-auth-client",
                "Targeted Auth Client",
                "gateway",
                "api-key",
                true,
                null,
                now,
                now));
            await store.UpsertClientKeyAsync(new CryptoApiClientKeyRecord(
                clientKeyId,
                clientId,
                "primary",
                "kid-targeted-auth",
                "api-key-secret",
                "pbkdf2-sha256-v1",
                "pbkdf2-sha256-v1$100000$salt$hash",
                "tar...uth",
                true,
                now,
                now,
                null,
                null,
                null,
                now.AddMinutes(-1)));
            await store.UpsertPolicyAsync(new CryptoApiPolicyRecord(
                boundPolicyId,
                "signing-bound",
                null,
                1,
                "{\"version\":1,\"allowedOperations\":[\"sign\"]}",
                true,
                now,
                now));
            await store.UpsertPolicyAsync(new CryptoApiPolicyRecord(
                unboundPolicyId,
                "verify-unbound",
                null,
                1,
                "{\"version\":1,\"allowedOperations\":[\"verify\"]}",
                true,
                now,
                now));
            await store.ReplaceClientPolicyBindingsAsync(clientId, [boundPolicyId]);

            CryptoApiClientAuthenticationState? authenticationState = await store.GetClientAuthenticationStateAsync("kid-targeted-auth");

            Assert.NotNull(authenticationState);
            Assert.Equal(clientId, authenticationState!.Client.ClientId);
            Assert.Equal(clientKeyId, authenticationState.Key.ClientKeyId);
            Assert.Equal("targeted-auth-client", authenticationState.Client.ClientName);
            Assert.Equal("kid-targeted-auth", authenticationState.Key.KeyIdentifier);
            Assert.Equal(new[] { boundPolicyId }, authenticationState.BoundPolicyIds);
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    [Fact]
    public async Task KeyAuthorizationStateQueryReturnsOnlySharedEnabledPoliciesForAlias()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-authorization-state-{Guid.NewGuid():N}.db");
        try
        {
            CryptoApiSharedPersistenceOptions options = new()
            {
                Provider = "Sqlite",
                ConnectionString = $"Data Source={databasePath}",
                AutoInitialize = true
            };

            SqliteCryptoApiSharedStateStore store = new(Options.Create(options));
            DateTimeOffset now = DateTimeOffset.UtcNow;
            Guid clientId = Guid.NewGuid();
            Guid aliasId = Guid.NewGuid();
            Guid sharedPolicyId = Guid.NewGuid();
            Guid clientOnlyPolicyId = Guid.NewGuid();
            Guid disabledSharedPolicyId = Guid.NewGuid();

            await store.UpsertClientAsync(new CryptoApiClientRecord(
                clientId,
                "targeted-authorization-client",
                "Targeted Authorization Client",
                "gateway",
                "api-key",
                true,
                null,
                now,
                now));
            await store.UpsertKeyAliasAsync(new CryptoApiKeyAliasRecord(
                aliasId,
                "payments-signer",
                "hsm-eu-primary",
                7,
                "Payments signing key",
                "A1B2C3D4",
                null,
                true,
                now,
                now));
            await store.UpsertPolicyAsync(new CryptoApiPolicyRecord(
                sharedPolicyId,
                "shared-sign",
                null,
                1,
                "{\"version\":1,\"allowedOperations\":[\"sign\"]}",
                true,
                now,
                now));
            await store.UpsertPolicyAsync(new CryptoApiPolicyRecord(
                clientOnlyPolicyId,
                "client-only",
                null,
                1,
                "{\"version\":1,\"allowedOperations\":[\"verify\"]}",
                true,
                now,
                now));
            await store.UpsertPolicyAsync(new CryptoApiPolicyRecord(
                disabledSharedPolicyId,
                "disabled-shared",
                null,
                1,
                "{\"version\":1,\"allowedOperations\":[\"unwrap\"]}",
                false,
                now,
                now));

            await store.ReplaceClientPolicyBindingsAsync(clientId, [sharedPolicyId, clientOnlyPolicyId, disabledSharedPolicyId]);
            await store.ReplaceKeyAliasPolicyBindingsAsync(aliasId, [sharedPolicyId, disabledSharedPolicyId]);

            CryptoApiKeyAuthorizationState authorizationState = await store.GetKeyAuthorizationStateAsync(clientId, "PAYMENTS-SIGNER");

            Assert.NotNull(authorizationState.Client);
            Assert.NotNull(authorizationState.Alias);
            Assert.Equal(clientId, authorizationState.Client!.ClientId);
            Assert.Equal(aliasId, authorizationState.Alias!.AliasId);
            CryptoApiPolicyRecord policy = Assert.Single(authorizationState.SharedPolicies);
            Assert.Equal(sharedPolicyId, policy.PolicyId);
            Assert.Equal("shared-sign", policy.PolicyName);
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    [Fact]
    public async Task GetAuthStateRevisionInitializesDatabaseOnlyOncePerProcess()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-init-once-{Guid.NewGuid():N}.db");
        try
        {
            CryptoApiSharedPersistenceOptions options = new()
            {
                Provider = "Sqlite",
                ConnectionString = $"Data Source={databasePath}",
                AutoInitialize = true
            };

            SqliteCryptoApiSharedStateStore store = new(Options.Create(options));

            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => store.GetAuthStateRevisionAsync()));
            await store.GetAuthStateRevisionAsync();
            await store.GetSnapshotAsync();

            Assert.Equal(1, store.DatabaseInitializationCount);
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    [Fact]
    public async Task SnapshotReadsDoNotReinitializeDatabaseAfterWarmUp()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-snapshot-warm-{Guid.NewGuid():N}.db");
        try
        {
            CryptoApiSharedPersistenceOptions options = new()
            {
                Provider = "Sqlite",
                ConnectionString = $"Data Source={databasePath}",
                AutoInitialize = true
            };

            SqliteCryptoApiSharedStateStore writer = new(Options.Create(options));
            Guid clientId = Guid.NewGuid();
            DateTimeOffset now = DateTimeOffset.UtcNow;

            await writer.UpsertClientAsync(new CryptoApiClientRecord(
                clientId,
                "warm-client",
                "Warm Client",
                "service",
                "api-key",
                true,
                null,
                now,
                now));

            SqliteCryptoApiSharedStateStore reader = new(Options.Create(options));

            await reader.GetSnapshotAsync();
            long afterWarmUp = reader.DatabaseInitializationCount;

            await reader.GetAuthStateRevisionAsync();
            await reader.GetSnapshotAsync();
            await reader.GetSnapshotAsync();

            Assert.Equal(1, afterWarmUp);
            Assert.Equal(afterWarmUp, reader.DatabaseInitializationCount);
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    private static void DeleteDatabaseArtifacts(string databasePath)
    {
        string walPath = databasePath + "-wal";
        string shmPath = databasePath + "-shm";

        if (File.Exists(databasePath)) File.Delete(databasePath);
        if (File.Exists(walPath)) File.Delete(walPath);
        if (File.Exists(shmPath)) File.Delete(shmPath);
    }
}
