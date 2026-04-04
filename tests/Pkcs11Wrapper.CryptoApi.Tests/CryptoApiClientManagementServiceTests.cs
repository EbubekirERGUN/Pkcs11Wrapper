using Microsoft.Extensions.Options;
using Npgsql;
using Pkcs11Wrapper.CryptoApi.Caching;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;
using static Pkcs11Wrapper.CryptoApi.Tests.PostgresTestEnvironment;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiClientManagementServiceTests
{
    [PostgresFact]
    public async Task CreateClientAndKeyStoresOnlyHashedSecretAndAuthenticatesSuccessfully()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        (ICryptoApiSharedStateStore store, CryptoApiClientManagementService management, CryptoApiClientAuthenticationService authentication) = CreateServices(scope.Options);

        CryptoApiManagedClient client = await management.CreateClientAsync(new CreateCryptoApiClientRequest(
            ClientName: "payments-gateway",
            DisplayName: "Payments Gateway",
            ApplicationType: "gateway",
            Notes: "Primary ingress application"));

        CryptoApiCreatedClientKey createdKey = await management.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(
            ClientId: client.ClientId,
            KeyName: "primary",
            ExpiresAtUtc: null));

        CryptoApiSharedStateSnapshot snapshot = await store.GetSnapshotAsync();
        CryptoApiClientKeyRecord persistedKey = Assert.Single(snapshot.ClientKeys);
        Assert.Equal(CryptoApiClientSecretHasher.Algorithm, persistedKey.SecretHashAlgorithm);
        Assert.NotEqual(createdKey.Secret, persistedKey.SecretHash);
        Assert.DoesNotContain(createdKey.Secret, persistedKey.SecretHash, StringComparison.Ordinal);
        Assert.NotNull(persistedKey.SecretHint);

        CryptoApiClientAuthenticationResult authenticated = await authentication.AuthenticateAsync(createdKey.KeyIdentifier, createdKey.Secret);

        Assert.True(authenticated.Succeeded);
        Assert.NotNull(authenticated.Client);
        Assert.Equal(client.ClientId, authenticated.Client.ClientId);
        Assert.Equal(createdKey.KeyIdentifier, authenticated.Client.KeyIdentifier);

        CryptoApiClientKeyRecord updatedKey = Assert.Single((await store.GetSnapshotAsync()).ClientKeys);
        Assert.NotNull(updatedKey.LastUsedAtUtc);
    }

    [PostgresFact]
    public async Task RevokeClientKeyPreventsFutureAuthentication()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        (_, CryptoApiClientManagementService management, CryptoApiClientAuthenticationService authentication) = CreateServices(scope.Options);

        CryptoApiManagedClient client = await management.CreateClientAsync(new CreateCryptoApiClientRequest(
            ClientName: "reporting-worker",
            DisplayName: "Reporting Worker",
            ApplicationType: "worker",
            Notes: null));
        CryptoApiCreatedClientKey key = await management.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(client.ClientId, "nightly", null));
        await management.RevokeClientKeyAsync(key.ClientKeyId, "Rotation superseded this key.");

        CryptoApiClientAuthenticationResult result = await authentication.AuthenticateAsync(key.KeyIdentifier, key.Secret);

        Assert.False(result.Succeeded);
        Assert.Equal("API key has been revoked.", result.FailureReason);
    }

    [PostgresFact]
    public async Task ExistingVersion1SharedStateDatabaseMigratesToCurrentSchema()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        await CreateVersion1DatabaseAsync(scope.Options.ConnectionString!);
        (ICryptoApiSharedStateStore store, CryptoApiClientManagementService management, _) = CreateServices(scope.Options);

        CryptoApiClientManagementSnapshot snapshot = await management.GetSnapshotAsync();
        CryptoApiSharedStateStatus status = await store.GetStatusAsync();

        Assert.True(snapshot.SharedPersistenceConfigured);
        Assert.Equal(CryptoApiSharedStateConstants.SchemaVersion, status.SchemaVersion);
        CryptoApiManagedClient client = Assert.Single(snapshot.Clients);
        Assert.Equal("service", client.ApplicationType);

        CryptoApiManagedClientKey key = Assert.Single(client.Keys);
        Assert.Equal("legacy-placeholder", key.SecretHashAlgorithm);
        Assert.Null(key.RevokedAtUtc);
        Assert.Null(key.LastUsedAtUtc);
    }

    private static (ICryptoApiSharedStateStore Store, CryptoApiClientManagementService Management, CryptoApiClientAuthenticationService Authentication) CreateServices(CryptoApiSharedPersistenceOptions options)
    {
        ICryptoApiSharedStateStore store = new PostgresCryptoApiSharedStateStore(Options.Create(options));
        ICryptoApiDistributedHotPathCache distributedHotPathCache = new NoOpCryptoApiDistributedHotPathCache();
        CryptoApiClientSecretGenerator generator = new();
        CryptoApiClientSecretHasher hasher = new();
        TimeProvider timeProvider = TimeProvider.System;
        CryptoApiClientManagementService management = new(store, generator, hasher, timeProvider);
        CryptoApiClientAuthenticationService authentication = new(store, distributedHotPathCache, hasher, timeProvider);
        return (store, management, authentication);
    }

    private static async Task CreateVersion1DatabaseAsync(string connectionString)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync();

        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE crypto_api_clients (
                client_id UUID PRIMARY KEY,
                client_name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                authentication_mode TEXT NOT NULL,
                is_enabled BOOLEAN NOT NULL,
                notes TEXT NULL,
                created_at_utc TIMESTAMPTZ NOT NULL,
                updated_at_utc TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE crypto_api_client_keys (
                client_key_id UUID PRIMARY KEY,
                client_id UUID NOT NULL,
                key_name TEXT NOT NULL,
                key_identifier TEXT NOT NULL UNIQUE,
                credential_type TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                secret_hint TEXT NULL,
                is_enabled BOOLEAN NOT NULL,
                created_at_utc TIMESTAMPTZ NOT NULL,
                updated_at_utc TIMESTAMPTZ NOT NULL,
                expires_at_utc TIMESTAMPTZ NULL,
                FOREIGN KEY(client_id) REFERENCES crypto_api_clients(client_id) ON DELETE CASCADE
            );

            CREATE TABLE crypto_api_key_aliases (
                alias_id UUID PRIMARY KEY,
                alias_name TEXT NOT NULL UNIQUE,
                slot_id BIGINT NULL,
                object_label TEXT NULL,
                object_id_hex TEXT NULL,
                notes TEXT NULL,
                is_enabled BOOLEAN NOT NULL,
                created_at_utc TIMESTAMPTZ NOT NULL,
                updated_at_utc TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE crypto_api_policies (
                policy_id UUID PRIMARY KEY,
                policy_name TEXT NOT NULL UNIQUE,
                description TEXT NULL,
                revision INTEGER NOT NULL,
                document_json TEXT NOT NULL,
                is_enabled BOOLEAN NOT NULL,
                created_at_utc TIMESTAMPTZ NOT NULL,
                updated_at_utc TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE crypto_api_client_policy_bindings (
                client_id UUID NOT NULL,
                policy_id UUID NOT NULL,
                bound_at_utc TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (client_id, policy_id)
            );

            CREATE TABLE crypto_api_key_alias_policy_bindings (
                alias_id UUID NOT NULL,
                policy_id UUID NOT NULL,
                bound_at_utc TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (alias_id, policy_id)
            );

            INSERT INTO crypto_api_clients (client_id, client_name, display_name, authentication_mode, is_enabled, notes, created_at_utc, updated_at_utc)
            VALUES ('00000000-0000-0000-0000-000000000001', 'legacy-client', 'Legacy Client', 'shared-secret', TRUE, NULL, '2026-04-03T10:00:00.0000000Z', '2026-04-03T10:00:00.0000000Z');

            INSERT INTO crypto_api_client_keys (client_key_id, client_id, key_name, key_identifier, credential_type, secret_hash, secret_hint, is_enabled, created_at_utc, updated_at_utc, expires_at_utc)
            VALUES ('00000000-0000-0000-0000-000000000101', '00000000-0000-0000-0000-000000000001', 'legacy-key', 'kid-legacy', 'shared-secret', 'sha256:placeholder', 'lega...lder', TRUE, '2026-04-03T10:00:00.0000000Z', '2026-04-03T10:00:00.0000000Z', NULL);
            """;
        await command.ExecuteNonQueryAsync();
    }
}
