using System.Diagnostics;
using Microsoft.Extensions.Options;
using Npgsql;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Observability;

namespace Pkcs11Wrapper.CryptoApi.SharedState;

public sealed class PostgresCryptoApiSharedStateStore(IOptions<CryptoApiSharedPersistenceOptions> options, CryptoApiMetrics? metrics = null) : ICryptoApiAuthoritativeSharedStateStore, ICryptoApiSharedStateMetricsSource, IAsyncDisposable
{
    private const string AuthStateRevisionMetadataKey = "auth_state_revision";
    private const string AuthStateRevisionNotificationChannelPrefix = "crypto_api_auth_state_";
    private const int DefaultMaxPoolSize = 32;
    private const string SchemaVersionMetadataKey = "schema_version";
    private static readonly TimeSpan AuthStateRevisionListenerReconnectDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan AuthStateRevisionListenerWaitTimeout = TimeSpan.FromSeconds(30);

    private readonly CryptoApiSharedPersistenceOptions _options = options.Value;
    private readonly string? _pooledConnectionString = NormalizePooledConnectionString(options.Value.ConnectionString);
    private readonly SemaphoreSlim _initializationGate = new(1, 1);
    private readonly SemaphoreSlim _authStateRevisionListenerGate = new(1, 1);
    private readonly CancellationTokenSource _listenerCancellationSource = new();
    private readonly string _authStateRevisionNotificationChannel = CreateAuthStateRevisionNotificationChannel(options.Value.ConnectionString);
    private readonly CryptoApiMetrics? _metrics = metrics;
    private volatile bool _databaseInitialized;
    private volatile bool _authStateRevisionListenerStarted;
    private long _databaseInitializationCount;
    private long _cachedAuthStateRevision;
    private long _authStateRevisionDatabaseReadCount;
    private int _disposeState;
    private Task? _authStateRevisionListenerTask;
    private TaskCompletionSource _authStateRevisionListenerReady = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal long DatabaseInitializationCount => Interlocked.Read(ref _databaseInitializationCount);

    internal long AuthStateRevisionDatabaseReadCount => Interlocked.Read(ref _authStateRevisionDatabaseReadCount);

    internal int EffectiveMaxPoolSize
        => string.IsNullOrWhiteSpace(_pooledConnectionString)
            ? 0
            : new NpgsqlConnectionStringBuilder(_pooledConnectionString).MaxPoolSize;

    public CryptoApiSharedStateMetricsSnapshot GetMetricsSnapshot()
        => new(
            Configured: IsConfigured(),
            Provider: CryptoApiSharedPersistenceDefaults.PostgresProvider,
            EffectiveMaxPoolSize: EffectiveMaxPoolSize);

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "success";

        if (!IsConfigured())
        {
            _metrics?.RecordSharedStateRequest("initialize", "unconfigured", stopwatch.Elapsed);
            return;
        }

        if (_databaseInitialized)
        {
            _metrics?.RecordSharedStateRequest("initialize", "already_initialized", stopwatch.Elapsed);
            return;
        }

        try
        {
            await _initializationGate.WaitAsync(cancellationToken);
            try
            {
                if (_databaseInitialized)
                {
                    result = "already_initialized";
                    return;
                }

                await using NpgsqlConnection connection = CreateConnection();
                await connection.OpenAsync(cancellationToken);

                if (_options.AutoInitialize)
                {
                    await EnsureSchemaAsync(connection, cancellationToken);
                }

                _databaseInitialized = true;
                Interlocked.Increment(ref _databaseInitializationCount);
                result = "initialized";
            }
            finally
            {
                _initializationGate.Release();
            }
        }
        catch
        {
            result = "error";
            throw;
        }
        finally
        {
            _metrics?.RecordSharedStateRequest("initialize", result, stopwatch.Elapsed);
        }
    }

    public async Task<CryptoApiSharedStateStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "success";

        if (!IsConfigured())
        {
            _metrics?.RecordSharedStateRequest("get_status", "unconfigured", stopwatch.Elapsed);
            return CreateUnconfiguredStatus();
        }

        try
        {
            await InitializeAsync(cancellationToken);

            await using NpgsqlConnection connection = CreateConnection();
            await connection.OpenAsync(cancellationToken);
            await EnsureSchemaAsync(connection, cancellationToken);

            return new CryptoApiSharedStateStatus(
                Configured: true,
                Provider: CryptoApiSharedPersistenceDefaults.PostgresProvider,
                ConnectionTarget: GetConnectionTarget(),
                SchemaVersion: await GetSchemaVersionAsync(connection, cancellationToken),
                ApiClientCount: await CountRowsAsync(connection, "crypto_api_clients", cancellationToken),
                ApiClientKeyCount: await CountRowsAsync(connection, "crypto_api_client_keys", cancellationToken),
                KeyAliasCount: await CountRowsAsync(connection, "crypto_api_key_aliases", cancellationToken),
                PolicyCount: await CountRowsAsync(connection, "crypto_api_policies", cancellationToken),
                ClientPolicyBindingCount: await CountRowsAsync(connection, "crypto_api_client_policy_bindings", cancellationToken),
                KeyAliasPolicyBindingCount: await CountRowsAsync(connection, "crypto_api_key_alias_policy_bindings", cancellationToken),
                SharedReadyAreas: CryptoApiSharedStateConstants.SharedReadyAreas);
        }
        catch
        {
            result = "error";
            throw;
        }
        finally
        {
            _metrics?.RecordSharedStateRequest("get_status", result, stopwatch.Elapsed);
        }
    }

    public async Task<long> GetAuthStateRevisionAsync(CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "success";

        if (!IsConfigured())
        {
            _metrics?.RecordSharedStateRequest("get_auth_state_revision", "unconfigured", stopwatch.Elapsed);
            return 0;
        }

        try
        {
            await InitializeAsync(cancellationToken);

            await EnsureAuthStateRevisionListenerStartedAsync(cancellationToken);

            long cachedRevision = Interlocked.Read(ref _cachedAuthStateRevision);
            if (cachedRevision > 0)
            {
                result = "cached";
                return cachedRevision;
            }

            await using NpgsqlConnection connection = CreateConnection();
            await connection.OpenAsync(cancellationToken);
            long revision = await ReadAuthStateRevisionFromDatabaseAsync(connection, cancellationToken);
            UpdateCachedAuthStateRevision(revision);
            result = "database";
            return revision;
        }
        catch
        {
            result = "error";
            throw;
        }
        finally
        {
            _metrics?.RecordSharedStateRequest("get_auth_state_revision", result, stopwatch.Elapsed);
        }
    }

    public async Task<CryptoApiClientAuthenticationState?> GetClientAuthenticationStateAsync(string keyIdentifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyIdentifier);

        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "found";

        if (!IsConfigured())
        {
            _metrics?.RecordSharedStateRequest("get_client_authentication_state", "unconfigured", stopwatch.Elapsed);
            return null;
        }

        try
        {
            await EnsureConfiguredAndInitializedAsync(cancellationToken);

            await using NpgsqlConnection connection = CreateConnection();
            await connection.OpenAsync(cancellationToken);

            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = """
            SELECT
                c.client_id,
                c.client_name,
                c.display_name,
                c.application_type,
                c.authentication_mode,
                c.is_enabled,
                c.notes,
                c.created_at_utc,
                c.updated_at_utc,
                k.client_key_id,
                k.key_name,
                k.key_identifier,
                k.credential_type,
                k.secret_hash_algorithm,
                k.secret_hash,
                k.secret_hint,
                k.is_enabled,
                k.created_at_utc,
                k.updated_at_utc,
                k.expires_at_utc,
                k.revoked_at_utc,
                k.revoked_reason,
                k.last_used_at_utc
            FROM crypto_api_client_keys k
            INNER JOIN crypto_api_clients c ON c.client_id = k.client_id
            WHERE k.key_identifier = @keyIdentifier
            LIMIT 1;
            """;
            AddText(command, "@keyIdentifier", keyIdentifier);

            CryptoApiClientRecord client;
            CryptoApiClientKeyRecord key;

            await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken))
            {
                if (!await reader.ReadAsync(cancellationToken))
                {
                    result = "not_found";
                    return null;
                }

                client = new CryptoApiClientRecord(
                    ClientId: reader.GetGuid(0),
                    ClientName: reader.GetString(1),
                    DisplayName: reader.GetString(2),
                    ApplicationType: reader.GetString(3),
                    AuthenticationMode: reader.GetString(4),
                    IsEnabled: reader.GetBoolean(5),
                    Notes: reader.IsDBNull(6) ? null : reader.GetString(6),
                    CreatedAtUtc: ReadTimestamp(reader, 7),
                    UpdatedAtUtc: ReadTimestamp(reader, 8));

                key = new CryptoApiClientKeyRecord(
                    ClientKeyId: reader.GetGuid(9),
                    ClientId: client.ClientId,
                    KeyName: reader.GetString(10),
                    KeyIdentifier: reader.GetString(11),
                    CredentialType: reader.GetString(12),
                    SecretHashAlgorithm: reader.GetString(13),
                    SecretHash: reader.GetString(14),
                    SecretHint: reader.IsDBNull(15) ? null : reader.GetString(15),
                    IsEnabled: reader.GetBoolean(16),
                    CreatedAtUtc: ReadTimestamp(reader, 17),
                    UpdatedAtUtc: ReadTimestamp(reader, 18),
                    ExpiresAtUtc: ReadNullableTimestamp(reader, 19),
                    RevokedAtUtc: ReadNullableTimestamp(reader, 20),
                    RevokedReason: reader.IsDBNull(21) ? null : reader.GetString(21),
                    LastUsedAtUtc: ReadNullableTimestamp(reader, 22));
            }

            Guid[] boundPolicyIds = await ReadClientBoundPolicyIdsAsync(connection, client.ClientId, cancellationToken);
            return new CryptoApiClientAuthenticationState(client, key, boundPolicyIds);
        }
        catch
        {
            result = "error";
            throw;
        }
        finally
        {
            _metrics?.RecordSharedStateRequest("get_client_authentication_state", result, stopwatch.Elapsed);
        }
    }

    public async Task<CryptoApiKeyAuthorizationState> GetKeyAuthorizationStateAsync(Guid clientId, string aliasName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(aliasName);

        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "success";

        if (!IsConfigured())
        {
            _metrics?.RecordSharedStateRequest("get_key_authorization_state", "unconfigured", stopwatch.Elapsed);
            return new CryptoApiKeyAuthorizationState(null, null, []);
        }

        try
        {
            await EnsureConfiguredAndInitializedAsync(cancellationToken);

            await using NpgsqlConnection connection = CreateConnection();
            await connection.OpenAsync(cancellationToken);

            CryptoApiClientRecord? client = await ReadClientByIdAsync(connection, clientId, cancellationToken);
            if (client is null)
            {
                result = "client_not_found";
                return new CryptoApiKeyAuthorizationState(null, null, []);
            }

            CryptoApiKeyAliasRecord? alias = await ReadKeyAliasByNameAsync(connection, aliasName, cancellationToken);
            if (alias is null)
            {
                result = "alias_not_found";
                return new CryptoApiKeyAuthorizationState(client, null, []);
            }

            IReadOnlyList<CryptoApiPolicyRecord> sharedPolicies = await ReadSharedPoliciesAsync(connection, clientId, alias.AliasId, cancellationToken);
            return new CryptoApiKeyAuthorizationState(client, alias, sharedPolicies);
        }
        catch
        {
            result = "error";
            throw;
        }
        finally
        {
            _metrics?.RecordSharedStateRequest("get_key_authorization_state", result, stopwatch.Elapsed);
        }
    }

    public async Task UpsertClientAsync(CryptoApiClientRecord client, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using NpgsqlConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using NpgsqlCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO crypto_api_clients (
                client_id,
                client_name,
                display_name,
                application_type,
                authentication_mode,
                is_enabled,
                notes,
                created_at_utc,
                updated_at_utc)
            VALUES (
                @clientId,
                @clientName,
                @displayName,
                @applicationType,
                @authenticationMode,
                @isEnabled,
                @notes,
                @createdAtUtc,
                @updatedAtUtc)
            ON CONFLICT (client_id) DO UPDATE SET
                client_name = EXCLUDED.client_name,
                display_name = EXCLUDED.display_name,
                application_type = EXCLUDED.application_type,
                authentication_mode = EXCLUDED.authentication_mode,
                is_enabled = EXCLUDED.is_enabled,
                notes = EXCLUDED.notes,
                updated_at_utc = EXCLUDED.updated_at_utc;
            """;
        AddGuid(command, "@clientId", client.ClientId);
        AddText(command, "@clientName", client.ClientName);
        AddText(command, "@displayName", client.DisplayName);
        AddText(command, "@applicationType", client.ApplicationType);
        AddText(command, "@authenticationMode", client.AuthenticationMode);
        AddBoolean(command, "@isEnabled", client.IsEnabled);
        AddNullableText(command, "@notes", client.Notes);
        AddTimestamp(command, "@createdAtUtc", client.CreatedAtUtc);
        AddTimestamp(command, "@updatedAtUtc", client.UpdatedAtUtc);

        await command.ExecuteNonQueryAsync(cancellationToken);
        _ = await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task UpsertClientKeyAsync(CryptoApiClientKeyRecord clientKey, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using NpgsqlConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using NpgsqlCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO crypto_api_client_keys (
                client_key_id,
                client_id,
                key_name,
                key_identifier,
                credential_type,
                secret_hash_algorithm,
                secret_hash,
                secret_hint,
                is_enabled,
                created_at_utc,
                updated_at_utc,
                expires_at_utc,
                revoked_at_utc,
                revoked_reason,
                last_used_at_utc)
            VALUES (
                @clientKeyId,
                @clientId,
                @keyName,
                @keyIdentifier,
                @credentialType,
                @secretHashAlgorithm,
                @secretHash,
                @secretHint,
                @isEnabled,
                @createdAtUtc,
                @updatedAtUtc,
                @expiresAtUtc,
                @revokedAtUtc,
                @revokedReason,
                @lastUsedAtUtc)
            ON CONFLICT (client_key_id) DO UPDATE SET
                client_id = EXCLUDED.client_id,
                key_name = EXCLUDED.key_name,
                key_identifier = EXCLUDED.key_identifier,
                credential_type = EXCLUDED.credential_type,
                secret_hash_algorithm = EXCLUDED.secret_hash_algorithm,
                secret_hash = EXCLUDED.secret_hash,
                secret_hint = EXCLUDED.secret_hint,
                is_enabled = EXCLUDED.is_enabled,
                updated_at_utc = EXCLUDED.updated_at_utc,
                expires_at_utc = EXCLUDED.expires_at_utc,
                revoked_at_utc = EXCLUDED.revoked_at_utc,
                revoked_reason = EXCLUDED.revoked_reason,
                last_used_at_utc = EXCLUDED.last_used_at_utc;
            """;
        AddGuid(command, "@clientKeyId", clientKey.ClientKeyId);
        AddGuid(command, "@clientId", clientKey.ClientId);
        AddText(command, "@keyName", clientKey.KeyName);
        AddText(command, "@keyIdentifier", clientKey.KeyIdentifier);
        AddText(command, "@credentialType", clientKey.CredentialType);
        AddText(command, "@secretHashAlgorithm", clientKey.SecretHashAlgorithm);
        AddText(command, "@secretHash", clientKey.SecretHash);
        AddNullableText(command, "@secretHint", clientKey.SecretHint);
        AddBoolean(command, "@isEnabled", clientKey.IsEnabled);
        AddTimestamp(command, "@createdAtUtc", clientKey.CreatedAtUtc);
        AddTimestamp(command, "@updatedAtUtc", clientKey.UpdatedAtUtc);
        AddNullableTimestamp(command, "@expiresAtUtc", clientKey.ExpiresAtUtc);
        AddNullableTimestamp(command, "@revokedAtUtc", clientKey.RevokedAtUtc);
        AddNullableText(command, "@revokedReason", clientKey.RevokedReason);
        AddNullableTimestamp(command, "@lastUsedAtUtc", clientKey.LastUsedAtUtc);

        await command.ExecuteNonQueryAsync(cancellationToken);
        _ = await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<bool> TryTouchClientKeyLastUsedAsync(Guid clientKeyId, DateTimeOffset lastUsedAtUtc, TimeSpan minimumInterval, CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "skipped";

        try
        {
            await EnsureConfiguredAndInitializedAsync(cancellationToken);

            await using NpgsqlConnection connection = CreateConnection();
            await connection.OpenAsync(cancellationToken);

            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = """
                UPDATE crypto_api_client_keys
                SET last_used_at_utc = @lastUsedAtUtc
                WHERE client_key_id = @clientKeyId
                  AND (last_used_at_utc IS NULL OR last_used_at_utc < @minimumLastUsedAtUtc);
                """;
            AddGuid(command, "@clientKeyId", clientKeyId);
            AddTimestamp(command, "@lastUsedAtUtc", lastUsedAtUtc);
            AddTimestamp(command, "@minimumLastUsedAtUtc", lastUsedAtUtc - minimumInterval);

            bool applied = await command.ExecuteNonQueryAsync(cancellationToken) > 0;
            result = applied ? "applied" : "skipped";
            return applied;
        }
        catch
        {
            result = "error";
            throw;
        }
        finally
        {
            _metrics?.RecordSharedStateRequest("touch_client_key_last_used", result, stopwatch.Elapsed);
        }
    }

    public async Task UpsertKeyAliasAsync(CryptoApiKeyAliasRecord keyAlias, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using NpgsqlConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using NpgsqlCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO crypto_api_key_aliases (
                alias_id,
                alias_name,
                route_group_name,
                device_route,
                slot_id,
                object_label,
                object_id_hex,
                notes,
                is_enabled,
                created_at_utc,
                updated_at_utc)
            VALUES (
                @aliasId,
                @aliasName,
                @routeGroupName,
                @deviceRoute,
                @slotId,
                @objectLabel,
                @objectIdHex,
                @notes,
                @isEnabled,
                @createdAtUtc,
                @updatedAtUtc)
            ON CONFLICT (alias_id) DO UPDATE SET
                alias_name = EXCLUDED.alias_name,
                route_group_name = EXCLUDED.route_group_name,
                device_route = EXCLUDED.device_route,
                slot_id = EXCLUDED.slot_id,
                object_label = EXCLUDED.object_label,
                object_id_hex = EXCLUDED.object_id_hex,
                notes = EXCLUDED.notes,
                is_enabled = EXCLUDED.is_enabled,
                updated_at_utc = EXCLUDED.updated_at_utc;
            """;
        AddGuid(command, "@aliasId", keyAlias.AliasId);
        AddText(command, "@aliasName", keyAlias.AliasName);
        AddNullableText(command, "@routeGroupName", keyAlias.RouteGroupName);
        AddNullableText(command, "@deviceRoute", keyAlias.DeviceRoute);
        AddNullableInt64(command, "@slotId", keyAlias.SlotId is null ? null : checked((long)keyAlias.SlotId.Value));
        AddNullableText(command, "@objectLabel", keyAlias.ObjectLabel);
        AddNullableText(command, "@objectIdHex", keyAlias.ObjectIdHex);
        AddNullableText(command, "@notes", keyAlias.Notes);
        AddBoolean(command, "@isEnabled", keyAlias.IsEnabled);
        AddTimestamp(command, "@createdAtUtc", keyAlias.CreatedAtUtc);
        AddTimestamp(command, "@updatedAtUtc", keyAlias.UpdatedAtUtc);

        await command.ExecuteNonQueryAsync(cancellationToken);
        _ = await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task UpsertPolicyAsync(CryptoApiPolicyRecord policy, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using NpgsqlConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using NpgsqlCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO crypto_api_policies (
                policy_id,
                policy_name,
                description,
                revision,
                document_json,
                is_enabled,
                created_at_utc,
                updated_at_utc)
            VALUES (
                @policyId,
                @policyName,
                @description,
                @revision,
                @documentJson,
                @isEnabled,
                @createdAtUtc,
                @updatedAtUtc)
            ON CONFLICT (policy_id) DO UPDATE SET
                policy_name = EXCLUDED.policy_name,
                description = EXCLUDED.description,
                revision = EXCLUDED.revision,
                document_json = EXCLUDED.document_json,
                is_enabled = EXCLUDED.is_enabled,
                updated_at_utc = EXCLUDED.updated_at_utc;
            """;
        AddGuid(command, "@policyId", policy.PolicyId);
        AddText(command, "@policyName", policy.PolicyName);
        AddNullableText(command, "@description", policy.Description);
        command.Parameters.AddWithValue("@revision", policy.Revision);
        AddText(command, "@documentJson", policy.DocumentJson);
        AddBoolean(command, "@isEnabled", policy.IsEnabled);
        AddTimestamp(command, "@createdAtUtc", policy.CreatedAtUtc);
        AddTimestamp(command, "@updatedAtUtc", policy.UpdatedAtUtc);

        await command.ExecuteNonQueryAsync(cancellationToken);
        _ = await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task ReplaceClientPolicyBindingsAsync(Guid clientId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using NpgsqlConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);

        await DeleteBindingsAsync(connection, transaction, "crypto_api_client_policy_bindings", "client_id", clientId, cancellationToken);
        foreach (Guid policyId in policyIds.Distinct())
        {
            await using NpgsqlCommand insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO crypto_api_client_policy_bindings (client_id, policy_id, bound_at_utc)
                VALUES (@clientId, @policyId, @boundAtUtc);
                """;
            AddGuid(insert, "@clientId", clientId);
            AddGuid(insert, "@policyId", policyId);
            AddTimestamp(insert, "@boundAtUtc", DateTimeOffset.UtcNow);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        _ = await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task ReplaceKeyAliasPolicyBindingsAsync(Guid aliasId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using NpgsqlConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);

        await DeleteBindingsAsync(connection, transaction, "crypto_api_key_alias_policy_bindings", "alias_id", aliasId, cancellationToken);
        foreach (Guid policyId in policyIds.Distinct())
        {
            await using NpgsqlCommand insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO crypto_api_key_alias_policy_bindings (alias_id, policy_id, bound_at_utc)
                VALUES (@aliasId, @policyId, @boundAtUtc);
                """;
            AddGuid(insert, "@aliasId", aliasId);
            AddGuid(insert, "@policyId", policyId);
            AddTimestamp(insert, "@boundAtUtc", DateTimeOffset.UtcNow);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        _ = await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<CryptoApiSharedStateSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using NpgsqlConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);

        return new CryptoApiSharedStateSnapshot(
            Clients: await ReadClientsAsync(connection, cancellationToken),
            ClientKeys: await ReadClientKeysAsync(connection, cancellationToken),
            KeyAliases: await ReadKeyAliasesAsync(connection, cancellationToken),
            Policies: await ReadPoliciesAsync(connection, cancellationToken),
            ClientPolicyBindings: await ReadClientPolicyBindingsAsync(connection, cancellationToken),
            KeyAliasPolicyBindings: await ReadKeyAliasPolicyBindingsAsync(connection, cancellationToken));
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeState, 1) != 0)
        {
            return;
        }

        _listenerCancellationSource.Cancel();

        if (_authStateRevisionListenerTask is not null)
        {
            try
            {
                await _authStateRevisionListenerTask;
            }
            catch (OperationCanceledException) when (_listenerCancellationSource.IsCancellationRequested)
            {
            }
        }

        _listenerCancellationSource.Dispose();
        _authStateRevisionListenerGate.Dispose();
        _initializationGate.Dispose();
    }

    private bool IsConfigured()
        => !string.IsNullOrWhiteSpace(_options.ConnectionString);

    private CryptoApiSharedStateStatus CreateUnconfiguredStatus()
        => new(
            Configured: false,
            Provider: CryptoApiSharedPersistenceDefaults.PostgresProvider,
            ConnectionTarget: null,
            SchemaVersion: 0,
            ApiClientCount: 0,
            ApiClientKeyCount: 0,
            KeyAliasCount: 0,
            PolicyCount: 0,
            ClientPolicyBindingCount: 0,
            KeyAliasPolicyBindingCount: 0,
            SharedReadyAreas: CryptoApiSharedStateConstants.SharedReadyAreas);

    private async Task EnsureConfiguredAndInitializedAsync(CancellationToken cancellationToken)
    {
        if (!IsConfigured())
        {
            throw new InvalidOperationException("Shared persistence is not configured.");
        }

        await InitializeAsync(cancellationToken);
    }

    private async Task EnsureAuthStateRevisionListenerStartedAsync(CancellationToken cancellationToken)
    {
        if (_authStateRevisionListenerStarted)
        {
            await WaitForAuthStateRevisionListenerReadyAsync(cancellationToken);
            return;
        }

        await _authStateRevisionListenerGate.WaitAsync(cancellationToken);
        try
        {
            if (_authStateRevisionListenerStarted)
            {
                return;
            }

            _authStateRevisionListenerReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _authStateRevisionListenerTask = Task.Run(() => ListenForAuthStateRevisionChangesAsync(_authStateRevisionListenerReady, _listenerCancellationSource.Token));
            _authStateRevisionListenerStarted = true;
        }
        finally
        {
            _authStateRevisionListenerGate.Release();
        }

        await WaitForAuthStateRevisionListenerReadyAsync(cancellationToken);
    }

    private async Task WaitForAuthStateRevisionListenerReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _authStateRevisionListenerReady.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
        }
        catch (TimeoutException)
        {
        }
    }

    private async Task ListenForAuthStateRevisionChangesAsync(TaskCompletionSource readySignal, CancellationToken cancellationToken)
    {
        bool readySignaled = false;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await InitializeAsync(cancellationToken);

                await using NpgsqlConnection connection = CreateListenerConnection();
                connection.Notification += HandleAuthStateRevisionNotification;

                try
                {
                    await connection.OpenAsync(cancellationToken);

                    await using NpgsqlCommand listen = connection.CreateCommand();
                    listen.CommandText = $"LISTEN {_authStateRevisionNotificationChannel};";
                    await listen.ExecuteNonQueryAsync(cancellationToken);

                    long revision = await ReadAuthStateRevisionFromDatabaseAsync(connection, cancellationToken);
                    UpdateCachedAuthStateRevision(revision);

                    if (!readySignaled)
                    {
                        readySignal.TrySetResult();
                        readySignaled = true;
                    }

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        _ = await connection.WaitAsync(AuthStateRevisionListenerWaitTimeout, cancellationToken);
                    }
                }
                finally
                {
                    connection.Notification -= HandleAuthStateRevisionNotification;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch
            {
                if (!readySignaled)
                {
                    readySignal.TrySetResult();
                    readySignaled = true;
                }

                try
                {
                    await Task.Delay(AuthStateRevisionListenerReconnectDelay, cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
            }
        }
    }

    private void HandleAuthStateRevisionNotification(object? sender, NpgsqlNotificationEventArgs args)
    {
        if (!string.Equals(args.Channel, _authStateRevisionNotificationChannel, StringComparison.Ordinal))
        {
            return;
        }

        if (long.TryParse(args.Payload, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out long revision))
        {
            UpdateCachedAuthStateRevision(revision);
        }
    }

    private NpgsqlConnection CreateConnection()
        => new(_pooledConnectionString);

    private NpgsqlConnection CreateListenerConnection()
    {
        NpgsqlConnectionStringBuilder builder = new(_options.ConnectionString)
        {
            Pooling = false
        };

        return new NpgsqlConnection(builder.ConnectionString);
    }

    private static string CreateAuthStateRevisionNotificationChannel(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return $"{AuthStateRevisionNotificationChannelPrefix}default";
        }

        NpgsqlConnectionStringBuilder builder = new(connectionString);
        string scope = string.Join('|',
            builder.Host ?? string.Empty,
            builder.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            builder.Database ?? string.Empty,
            builder.SearchPath ?? string.Empty);
        byte[] hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(scope));
        string suffix = Convert.ToHexString(hash.AsSpan(0, 12)).ToLowerInvariant();
        return $"{AuthStateRevisionNotificationChannelPrefix}{suffix}";
    }

    private static string? NormalizePooledConnectionString(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return connectionString;
        }

        NpgsqlConnectionStringBuilder builder = new(connectionString);
        if (builder.Pooling && !SpecifiesMaxPoolSize(connectionString))
        {
            builder.MaxPoolSize = DefaultMaxPoolSize;
        }

        return builder.ConnectionString;
    }

    private static bool SpecifiesMaxPoolSize(string connectionString)
    {
        string compact = connectionString.Replace(" ", string.Empty, StringComparison.Ordinal);
        return compact.Contains("maxpoolsize=", StringComparison.OrdinalIgnoreCase)
            || compact.Contains("maximumpoolsize=", StringComparison.OrdinalIgnoreCase)
            || connectionString.Contains("Max Pool Size=", StringComparison.OrdinalIgnoreCase)
            || connectionString.Contains("Maximum Pool Size=", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task EnsureSchemaAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS crypto_api_clients (
                client_id UUID PRIMARY KEY,
                client_name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                application_type TEXT NOT NULL DEFAULT 'service',
                authentication_mode TEXT NOT NULL,
                is_enabled BOOLEAN NOT NULL,
                notes TEXT NULL,
                created_at_utc TIMESTAMPTZ NOT NULL,
                updated_at_utc TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crypto_api_client_keys (
                client_key_id UUID PRIMARY KEY,
                client_id UUID NOT NULL,
                key_name TEXT NOT NULL,
                key_identifier TEXT NOT NULL UNIQUE,
                credential_type TEXT NOT NULL,
                secret_hash_algorithm TEXT NOT NULL DEFAULT 'legacy-placeholder',
                secret_hash TEXT NOT NULL,
                secret_hint TEXT NULL,
                is_enabled BOOLEAN NOT NULL,
                created_at_utc TIMESTAMPTZ NOT NULL,
                updated_at_utc TIMESTAMPTZ NOT NULL,
                expires_at_utc TIMESTAMPTZ NULL,
                revoked_at_utc TIMESTAMPTZ NULL,
                revoked_reason TEXT NULL,
                last_used_at_utc TIMESTAMPTZ NULL,
                CONSTRAINT fk_crypto_api_client_keys_client FOREIGN KEY (client_id) REFERENCES crypto_api_clients (client_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS crypto_api_key_aliases (
                alias_id UUID PRIMARY KEY,
                alias_name TEXT NOT NULL UNIQUE,
                route_group_name TEXT NULL,
                device_route TEXT NULL,
                slot_id BIGINT NULL,
                object_label TEXT NULL,
                object_id_hex TEXT NULL,
                notes TEXT NULL,
                is_enabled BOOLEAN NOT NULL,
                created_at_utc TIMESTAMPTZ NOT NULL,
                updated_at_utc TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crypto_api_policies (
                policy_id UUID PRIMARY KEY,
                policy_name TEXT NOT NULL UNIQUE,
                description TEXT NULL,
                revision INTEGER NOT NULL,
                document_json TEXT NOT NULL,
                is_enabled BOOLEAN NOT NULL,
                created_at_utc TIMESTAMPTZ NOT NULL,
                updated_at_utc TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crypto_api_client_policy_bindings (
                client_id UUID NOT NULL,
                policy_id UUID NOT NULL,
                bound_at_utc TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (client_id, policy_id),
                CONSTRAINT fk_crypto_api_client_policy_bindings_client FOREIGN KEY (client_id) REFERENCES crypto_api_clients (client_id) ON DELETE CASCADE,
                CONSTRAINT fk_crypto_api_client_policy_bindings_policy FOREIGN KEY (policy_id) REFERENCES crypto_api_policies (policy_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS crypto_api_key_alias_policy_bindings (
                alias_id UUID NOT NULL,
                policy_id UUID NOT NULL,
                bound_at_utc TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (alias_id, policy_id),
                CONSTRAINT fk_crypto_api_key_alias_policy_bindings_alias FOREIGN KEY (alias_id) REFERENCES crypto_api_key_aliases (alias_id) ON DELETE CASCADE,
                CONSTRAINT fk_crypto_api_key_alias_policy_bindings_policy FOREIGN KEY (policy_id) REFERENCES crypto_api_policies (policy_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS crypto_api_metadata (
                metadata_key TEXT PRIMARY KEY,
                metadata_value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS ix_crypto_api_client_keys_client_id
                ON crypto_api_client_keys(client_id);

            CREATE INDEX IF NOT EXISTS ix_crypto_api_client_keys_key_identifier
                ON crypto_api_client_keys(key_identifier);

            CREATE INDEX IF NOT EXISTS ix_crypto_api_client_policy_bindings_policy_id
                ON crypto_api_client_policy_bindings(policy_id);

            CREATE INDEX IF NOT EXISTS ix_crypto_api_key_alias_policy_bindings_policy_id
                ON crypto_api_key_alias_policy_bindings(policy_id);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);

        await EnsureColumnExistsAsync(connection, "crypto_api_clients", "application_type", "TEXT NOT NULL DEFAULT 'service'", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_client_keys", "secret_hash_algorithm", "TEXT NOT NULL DEFAULT 'legacy-placeholder'", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_client_keys", "revoked_at_utc", "TIMESTAMPTZ NULL", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_client_keys", "revoked_reason", "TEXT NULL", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_client_keys", "last_used_at_utc", "TIMESTAMPTZ NULL", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_key_aliases", "route_group_name", "TEXT NULL", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_key_aliases", "device_route", "TEXT NULL", cancellationToken);

        await using NpgsqlCommand metadata = connection.CreateCommand();
        metadata.CommandText = """
            INSERT INTO crypto_api_metadata (metadata_key, metadata_value)
            VALUES (@authStateRevisionKey, '1')
            ON CONFLICT (metadata_key) DO NOTHING;

            INSERT INTO crypto_api_metadata (metadata_key, metadata_value)
            VALUES (@schemaVersionKey, @schemaVersion)
            ON CONFLICT (metadata_key) DO UPDATE
            SET metadata_value = EXCLUDED.metadata_value;
            """;
        AddText(metadata, "@authStateRevisionKey", AuthStateRevisionMetadataKey);
        AddText(metadata, "@schemaVersionKey", SchemaVersionMetadataKey);
        AddText(metadata, "@schemaVersion", CryptoApiSharedStateConstants.SchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture));
        await metadata.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task EnsureColumnExistsAsync(NpgsqlConnection connection, string tableName, string columnName, string sqlTypeClause, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE {tableName} ADD COLUMN IF NOT EXISTS {columnName} {sqlTypeClause};";
        await alter.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<int> CountRowsAsync(NpgsqlConnection connection, string tableName, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {tableName};";
        object? value = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<int> GetSchemaVersionAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = "SELECT metadata_value FROM crypto_api_metadata WHERE metadata_key = @metadataKey;";
        AddText(command, "@metadataKey", SchemaVersionMetadataKey);
        object? value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null
            ? CryptoApiSharedStateConstants.SchemaVersion
            : Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<long> ReadAuthStateRevisionFromDatabaseAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _authStateRevisionDatabaseReadCount);
        _metrics?.RecordSharedStateDatabaseRead("auth_state_revision");

        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = "SELECT metadata_value FROM crypto_api_metadata WHERE metadata_key = @metadataKey;";
        AddText(command, "@metadataKey", AuthStateRevisionMetadataKey);
        object? value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null
            ? 1
            : Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<Guid[]> ReadClientBoundPolicyIdsAsync(NpgsqlConnection connection, Guid clientId, CancellationToken cancellationToken)
    {
        List<Guid> policyIds = [];
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT policy_id
            FROM crypto_api_client_policy_bindings
            WHERE client_id = @clientId
            ORDER BY policy_id;
            """;
        AddGuid(command, "@clientId", clientId);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            policyIds.Add(reader.GetGuid(0));
        }

        return policyIds.ToArray();
    }

    private static async Task<CryptoApiClientRecord?> ReadClientByIdAsync(NpgsqlConnection connection, Guid clientId, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_id, client_name, display_name, application_type, authentication_mode, is_enabled, notes, created_at_utc, updated_at_utc
            FROM crypto_api_clients
            WHERE client_id = @clientId
            LIMIT 1;
            """;
        AddGuid(command, "@clientId", clientId);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new CryptoApiClientRecord(
            ClientId: reader.GetGuid(0),
            ClientName: reader.GetString(1),
            DisplayName: reader.GetString(2),
            ApplicationType: reader.GetString(3),
            AuthenticationMode: reader.GetString(4),
            IsEnabled: reader.GetBoolean(5),
            Notes: reader.IsDBNull(6) ? null : reader.GetString(6),
            CreatedAtUtc: ReadTimestamp(reader, 7),
            UpdatedAtUtc: ReadTimestamp(reader, 8));
    }

    private static async Task<CryptoApiKeyAliasRecord?> ReadKeyAliasByNameAsync(NpgsqlConnection connection, string aliasName, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT alias_id, alias_name, route_group_name, device_route, slot_id, object_label, object_id_hex, notes, is_enabled, created_at_utc, updated_at_utc
            FROM crypto_api_key_aliases
            WHERE lower(alias_name) = lower(@aliasName)
            LIMIT 1;
            """;
        AddText(command, "@aliasName", aliasName);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new CryptoApiKeyAliasRecord(
            AliasId: reader.GetGuid(0),
            AliasName: reader.GetString(1),
            RouteGroupName: reader.IsDBNull(2) ? null : reader.GetString(2),
            DeviceRoute: reader.IsDBNull(3) ? null : reader.GetString(3),
            SlotId: reader.IsDBNull(4) ? null : checked((ulong)reader.GetInt64(4)),
            ObjectLabel: reader.IsDBNull(5) ? null : reader.GetString(5),
            ObjectIdHex: reader.IsDBNull(6) ? null : reader.GetString(6),
            Notes: reader.IsDBNull(7) ? null : reader.GetString(7),
            IsEnabled: reader.GetBoolean(8),
            CreatedAtUtc: ReadTimestamp(reader, 9),
            UpdatedAtUtc: ReadTimestamp(reader, 10));
    }

    private static async Task<IReadOnlyList<CryptoApiPolicyRecord>> ReadSharedPoliciesAsync(NpgsqlConnection connection, Guid clientId, Guid aliasId, CancellationToken cancellationToken)
    {
        List<CryptoApiPolicyRecord> policies = [];
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT DISTINCT p.policy_id, p.policy_name, p.description, p.revision, p.document_json, p.is_enabled, p.created_at_utc, p.updated_at_utc
            FROM crypto_api_policies p
            INNER JOIN crypto_api_client_policy_bindings cpb ON cpb.policy_id = p.policy_id
            INNER JOIN crypto_api_key_alias_policy_bindings kapb ON kapb.policy_id = p.policy_id
            WHERE cpb.client_id = @clientId
              AND kapb.alias_id = @aliasId
              AND p.is_enabled = TRUE
            ORDER BY p.policy_name;
            """;
        AddGuid(command, "@clientId", clientId);
        AddGuid(command, "@aliasId", aliasId);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            policies.Add(new CryptoApiPolicyRecord(
                PolicyId: reader.GetGuid(0),
                PolicyName: reader.GetString(1),
                Description: reader.IsDBNull(2) ? null : reader.GetString(2),
                Revision: reader.GetInt32(3),
                DocumentJson: reader.GetString(4),
                IsEnabled: reader.GetBoolean(5),
                CreatedAtUtc: ReadTimestamp(reader, 6),
                UpdatedAtUtc: ReadTimestamp(reader, 7)));
        }

        return policies;
    }

    private async Task<long> IncrementAuthStateRevisionAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            WITH next_revision AS (
                INSERT INTO crypto_api_metadata (metadata_key, metadata_value)
                VALUES (@metadataKey, '2')
                ON CONFLICT (metadata_key) DO UPDATE
                SET metadata_value = CAST(CAST(crypto_api_metadata.metadata_value AS BIGINT) + 1 AS TEXT)
                RETURNING metadata_value)
            SELECT CAST(metadata_value AS BIGINT)
            FROM next_revision;
            """;
        AddText(command, "@metadataKey", AuthStateRevisionMetadataKey);
        object? value = await command.ExecuteScalarAsync(cancellationToken);
        long revision = value is null
            ? 0
            : Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture);

        if (revision > 0)
        {
            UpdateCachedAuthStateRevision(revision);
            await NotifyAuthStateRevisionChangedAsync(connection, transaction, _authStateRevisionNotificationChannel, revision, cancellationToken);
        }

        return revision;
    }

    private static async Task NotifyAuthStateRevisionChangedAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string channel, long revision, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT pg_notify(@channel, @payload);";
        AddText(command, "@channel", channel);
        AddText(command, "@payload", revision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private void UpdateCachedAuthStateRevision(long revision)
    {
        if (revision <= 0)
        {
            return;
        }

        while (true)
        {
            long currentRevision = Interlocked.Read(ref _cachedAuthStateRevision);
            if (currentRevision >= revision)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref _cachedAuthStateRevision, revision, currentRevision) == currentRevision)
            {
                return;
            }
        }
    }

    private string? GetConnectionTarget()
    {
        NpgsqlConnectionStringBuilder builder = new(_options.ConnectionString);
        string host = string.IsNullOrWhiteSpace(builder.Host) ? "localhost" : builder.Host;
        string database = string.IsNullOrWhiteSpace(builder.Database) ? "postgres" : builder.Database;
        string target = $"{host}:{builder.Port}/{database}";
        return string.IsNullOrWhiteSpace(builder.SearchPath)
            ? target
            : $"{target}?search_path={builder.SearchPath}";
    }

    private static async Task DeleteBindingsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string tableName, string keyColumn, Guid keyValue, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = $"DELETE FROM {tableName} WHERE {keyColumn} = @keyValue;";
        AddGuid(delete, "@keyValue", keyValue);
        await delete.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<IReadOnlyList<CryptoApiClientRecord>> ReadClientsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiClientRecord> clients = [];
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_id, client_name, display_name, application_type, authentication_mode, is_enabled, notes, created_at_utc, updated_at_utc
            FROM crypto_api_clients
            ORDER BY client_name;
            """;
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            clients.Add(new CryptoApiClientRecord(
                ClientId: reader.GetGuid(0),
                ClientName: reader.GetString(1),
                DisplayName: reader.GetString(2),
                ApplicationType: reader.GetString(3),
                AuthenticationMode: reader.GetString(4),
                IsEnabled: reader.GetBoolean(5),
                Notes: reader.IsDBNull(6) ? null : reader.GetString(6),
                CreatedAtUtc: ReadTimestamp(reader, 7),
                UpdatedAtUtc: ReadTimestamp(reader, 8)));
        }

        return clients;
    }

    private static async Task<IReadOnlyList<CryptoApiClientKeyRecord>> ReadClientKeysAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiClientKeyRecord> clientKeys = [];
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_key_id, client_id, key_name, key_identifier, credential_type, secret_hash_algorithm, secret_hash, secret_hint, is_enabled, created_at_utc, updated_at_utc, expires_at_utc, revoked_at_utc, revoked_reason, last_used_at_utc
            FROM crypto_api_client_keys
            ORDER BY key_name;
            """;
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            clientKeys.Add(new CryptoApiClientKeyRecord(
                ClientKeyId: reader.GetGuid(0),
                ClientId: reader.GetGuid(1),
                KeyName: reader.GetString(2),
                KeyIdentifier: reader.GetString(3),
                CredentialType: reader.GetString(4),
                SecretHashAlgorithm: reader.GetString(5),
                SecretHash: reader.GetString(6),
                SecretHint: reader.IsDBNull(7) ? null : reader.GetString(7),
                IsEnabled: reader.GetBoolean(8),
                CreatedAtUtc: ReadTimestamp(reader, 9),
                UpdatedAtUtc: ReadTimestamp(reader, 10),
                ExpiresAtUtc: ReadNullableTimestamp(reader, 11),
                RevokedAtUtc: ReadNullableTimestamp(reader, 12),
                RevokedReason: reader.IsDBNull(13) ? null : reader.GetString(13),
                LastUsedAtUtc: ReadNullableTimestamp(reader, 14)));
        }

        return clientKeys;
    }

    private static async Task<IReadOnlyList<CryptoApiKeyAliasRecord>> ReadKeyAliasesAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiKeyAliasRecord> aliases = [];
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT alias_id, alias_name, route_group_name, device_route, slot_id, object_label, object_id_hex, notes, is_enabled, created_at_utc, updated_at_utc
            FROM crypto_api_key_aliases
            ORDER BY alias_name;
            """;
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            aliases.Add(new CryptoApiKeyAliasRecord(
                AliasId: reader.GetGuid(0),
                AliasName: reader.GetString(1),
                RouteGroupName: reader.IsDBNull(2) ? null : reader.GetString(2),
                DeviceRoute: reader.IsDBNull(3) ? null : reader.GetString(3),
                SlotId: reader.IsDBNull(4) ? null : checked((ulong)reader.GetInt64(4)),
                ObjectLabel: reader.IsDBNull(5) ? null : reader.GetString(5),
                ObjectIdHex: reader.IsDBNull(6) ? null : reader.GetString(6),
                Notes: reader.IsDBNull(7) ? null : reader.GetString(7),
                IsEnabled: reader.GetBoolean(8),
                CreatedAtUtc: ReadTimestamp(reader, 9),
                UpdatedAtUtc: ReadTimestamp(reader, 10)));
        }

        return aliases;
    }

    private static async Task<IReadOnlyList<CryptoApiPolicyRecord>> ReadPoliciesAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiPolicyRecord> policies = [];
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT policy_id, policy_name, description, revision, document_json, is_enabled, created_at_utc, updated_at_utc
            FROM crypto_api_policies
            ORDER BY policy_name;
            """;
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            policies.Add(new CryptoApiPolicyRecord(
                PolicyId: reader.GetGuid(0),
                PolicyName: reader.GetString(1),
                Description: reader.IsDBNull(2) ? null : reader.GetString(2),
                Revision: reader.GetInt32(3),
                DocumentJson: reader.GetString(4),
                IsEnabled: reader.GetBoolean(5),
                CreatedAtUtc: ReadTimestamp(reader, 6),
                UpdatedAtUtc: ReadTimestamp(reader, 7)));
        }

        return policies;
    }

    private static async Task<IReadOnlyList<CryptoApiClientPolicyBinding>> ReadClientPolicyBindingsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiClientPolicyBinding> bindings = [];
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_id, policy_id, bound_at_utc
            FROM crypto_api_client_policy_bindings
            ORDER BY client_id, policy_id;
            """;
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            bindings.Add(new CryptoApiClientPolicyBinding(
                ClientId: reader.GetGuid(0),
                PolicyId: reader.GetGuid(1),
                BoundAtUtc: ReadTimestamp(reader, 2)));
        }

        return bindings;
    }

    private static async Task<IReadOnlyList<CryptoApiKeyAliasPolicyBinding>> ReadKeyAliasPolicyBindingsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiKeyAliasPolicyBinding> bindings = [];
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT alias_id, policy_id, bound_at_utc
            FROM crypto_api_key_alias_policy_bindings
            ORDER BY alias_id, policy_id;
            """;
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            bindings.Add(new CryptoApiKeyAliasPolicyBinding(
                AliasId: reader.GetGuid(0),
                PolicyId: reader.GetGuid(1),
                BoundAtUtc: ReadTimestamp(reader, 2)));
        }

        return bindings;
    }

    private static DateTimeOffset ReadTimestamp(NpgsqlDataReader reader, int ordinal)
    {
        DateTime value = reader.GetDateTime(ordinal);
        if (value.Kind == DateTimeKind.Unspecified)
        {
            value = DateTime.SpecifyKind(value, DateTimeKind.Utc);
        }
        else if (value.Kind == DateTimeKind.Local)
        {
            value = value.ToUniversalTime();
        }

        return new DateTimeOffset(value, TimeSpan.Zero);
    }

    private static DateTimeOffset? ReadNullableTimestamp(NpgsqlDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal)
            ? null
            : ReadTimestamp(reader, ordinal);

    private static void AddGuid(NpgsqlCommand command, string parameterName, Guid value)
        => command.Parameters.AddWithValue(parameterName, value);

    private static void AddText(NpgsqlCommand command, string parameterName, string value)
        => command.Parameters.AddWithValue(parameterName, value);

    private static void AddNullableText(NpgsqlCommand command, string parameterName, string? value)
        => command.Parameters.AddWithValue(parameterName, value ?? (object)DBNull.Value);

    private static void AddNullableInt64(NpgsqlCommand command, string parameterName, long? value)
        => command.Parameters.AddWithValue(parameterName, value ?? (object)DBNull.Value);

    private static void AddBoolean(NpgsqlCommand command, string parameterName, bool value)
        => command.Parameters.AddWithValue(parameterName, value);

    private static void AddTimestamp(NpgsqlCommand command, string parameterName, DateTimeOffset value)
        => command.Parameters.AddWithValue(parameterName, value.UtcDateTime);

    private static void AddNullableTimestamp(NpgsqlCommand command, string parameterName, DateTimeOffset? value)
        => command.Parameters.AddWithValue(parameterName, value?.UtcDateTime ?? (object)DBNull.Value);
}
