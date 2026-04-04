using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Configuration;

namespace Pkcs11Wrapper.CryptoApi.SharedState;

public sealed class SqliteCryptoApiSharedStateStore(IOptions<CryptoApiSharedPersistenceOptions> options) : ICryptoApiSharedStateStore
{
    private const string AuthStateRevisionMetadataKey = "auth_state_revision";

    private readonly CryptoApiSharedPersistenceOptions _options = options.Value;
    private readonly SemaphoreSlim _initializationGate = new(1, 1);
    private volatile bool _databaseInitialized;
    private long _databaseInitializationCount;

    internal long DatabaseInitializationCount => Interlocked.Read(ref _databaseInitializationCount);

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConfigured())
        {
            return;
        }

        if (_databaseInitialized)
        {
            return;
        }

        await _initializationGate.WaitAsync(cancellationToken);
        try
        {
            if (_databaseInitialized)
            {
                return;
            }

            await using SqliteConnection connection = CreateConnection();
            await connection.OpenAsync(cancellationToken);
            await PrepareConnectionAsync(connection, cancellationToken);
            await ConfigureDatabaseAsync(connection, cancellationToken);

            if (_options.AutoInitialize)
            {
                await EnsureSchemaAsync(connection, cancellationToken);
            }

            _databaseInitialized = true;
            Interlocked.Increment(ref _databaseInitializationCount);
        }
        finally
        {
            _initializationGate.Release();
        }
    }

    public async Task<CryptoApiSharedStateStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConfigured())
        {
            return CreateUnconfiguredStatus();
        }

        await InitializeAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);
        await EnsureSchemaAsync(connection, cancellationToken);

        return new CryptoApiSharedStateStatus(
            Configured: true,
            Provider: CryptoApiSharedPersistenceDefaults.SqliteProvider,
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

    public async Task<long> GetAuthStateRevisionAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConfigured())
        {
            return 0;
        }

        await InitializeAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);
        return await GetAuthStateRevisionCoreAsync(connection, cancellationToken);
    }

    public async Task<CryptoApiClientAuthenticationState?> GetClientAuthenticationStateAsync(string keyIdentifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyIdentifier);

        if (!IsConfigured())
        {
            return null;
        }

        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
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
            WHERE k.key_identifier = $keyIdentifier
            LIMIT 1;
            """;
        AddText(command, "$keyIdentifier", keyIdentifier);

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        CryptoApiClientRecord client = new(
            ClientId: Guid.Parse(reader.GetString(0)),
            ClientName: reader.GetString(1),
            DisplayName: reader.GetString(2),
            ApplicationType: reader.GetString(3),
            AuthenticationMode: reader.GetString(4),
            IsEnabled: reader.GetBoolean(5),
            Notes: reader.IsDBNull(6) ? null : reader.GetString(6),
            CreatedAtUtc: ParseTimestamp(reader.GetString(7)),
            UpdatedAtUtc: ParseTimestamp(reader.GetString(8)));

        CryptoApiClientKeyRecord key = new(
            ClientKeyId: Guid.Parse(reader.GetString(9)),
            ClientId: client.ClientId,
            KeyName: reader.GetString(10),
            KeyIdentifier: reader.GetString(11),
            CredentialType: reader.GetString(12),
            SecretHashAlgorithm: reader.GetString(13),
            SecretHash: reader.GetString(14),
            SecretHint: reader.IsDBNull(15) ? null : reader.GetString(15),
            IsEnabled: reader.GetBoolean(16),
            CreatedAtUtc: ParseTimestamp(reader.GetString(17)),
            UpdatedAtUtc: ParseTimestamp(reader.GetString(18)),
            ExpiresAtUtc: reader.IsDBNull(19) ? null : ParseTimestamp(reader.GetString(19)),
            RevokedAtUtc: reader.IsDBNull(20) ? null : ParseTimestamp(reader.GetString(20)),
            RevokedReason: reader.IsDBNull(21) ? null : reader.GetString(21),
            LastUsedAtUtc: reader.IsDBNull(22) ? null : ParseTimestamp(reader.GetString(22)));

        Guid[] boundPolicyIds = await ReadClientBoundPolicyIdsAsync(connection, client.ClientId, cancellationToken);
        return new CryptoApiClientAuthenticationState(client, key, boundPolicyIds);
    }

    public async Task<CryptoApiKeyAuthorizationState> GetKeyAuthorizationStateAsync(Guid clientId, string aliasName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(aliasName);

        if (!IsConfigured())
        {
            return new CryptoApiKeyAuthorizationState(null, null, []);
        }

        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);

        CryptoApiClientRecord? client = await ReadClientByIdAsync(connection, clientId, cancellationToken);
        if (client is null)
        {
            return new CryptoApiKeyAuthorizationState(null, null, []);
        }

        CryptoApiKeyAliasRecord? alias = await ReadKeyAliasByNameAsync(connection, aliasName, cancellationToken);
        if (alias is null)
        {
            return new CryptoApiKeyAuthorizationState(client, null, []);
        }

        IReadOnlyList<CryptoApiPolicyRecord> sharedPolicies = await ReadSharedPoliciesAsync(connection, clientId, alias.AliasId, cancellationToken);
        return new CryptoApiKeyAuthorizationState(client, alias, sharedPolicies);
    }

    public async Task UpsertClientAsync(CryptoApiClientRecord client, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
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
                $clientId,
                $clientName,
                $displayName,
                $applicationType,
                $authenticationMode,
                $isEnabled,
                $notes,
                $createdAtUtc,
                $updatedAtUtc)
            ON CONFLICT(client_id) DO UPDATE SET
                client_name = excluded.client_name,
                display_name = excluded.display_name,
                application_type = excluded.application_type,
                authentication_mode = excluded.authentication_mode,
                is_enabled = excluded.is_enabled,
                notes = excluded.notes,
                updated_at_utc = excluded.updated_at_utc;
            """;
        AddText(command, "$clientId", client.ClientId.ToString("D", CultureInfo.InvariantCulture));
        AddText(command, "$clientName", client.ClientName);
        AddText(command, "$displayName", client.DisplayName);
        AddText(command, "$applicationType", client.ApplicationType);
        AddText(command, "$authenticationMode", client.AuthenticationMode);
        AddBoolean(command, "$isEnabled", client.IsEnabled);
        AddNullableText(command, "$notes", client.Notes);
        AddText(command, "$createdAtUtc", FormatTimestamp(client.CreatedAtUtc));
        AddText(command, "$updatedAtUtc", FormatTimestamp(client.UpdatedAtUtc));

        await command.ExecuteNonQueryAsync(cancellationToken);
        await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task UpsertClientKeyAsync(CryptoApiClientKeyRecord clientKey, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
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
                $clientKeyId,
                $clientId,
                $keyName,
                $keyIdentifier,
                $credentialType,
                $secretHashAlgorithm,
                $secretHash,
                $secretHint,
                $isEnabled,
                $createdAtUtc,
                $updatedAtUtc,
                $expiresAtUtc,
                $revokedAtUtc,
                $revokedReason,
                $lastUsedAtUtc)
            ON CONFLICT(client_key_id) DO UPDATE SET
                client_id = excluded.client_id,
                key_name = excluded.key_name,
                key_identifier = excluded.key_identifier,
                credential_type = excluded.credential_type,
                secret_hash_algorithm = excluded.secret_hash_algorithm,
                secret_hash = excluded.secret_hash,
                secret_hint = excluded.secret_hint,
                is_enabled = excluded.is_enabled,
                updated_at_utc = excluded.updated_at_utc,
                expires_at_utc = excluded.expires_at_utc,
                revoked_at_utc = excluded.revoked_at_utc,
                revoked_reason = excluded.revoked_reason,
                last_used_at_utc = excluded.last_used_at_utc;
            """;
        AddText(command, "$clientKeyId", clientKey.ClientKeyId.ToString("D", CultureInfo.InvariantCulture));
        AddText(command, "$clientId", clientKey.ClientId.ToString("D", CultureInfo.InvariantCulture));
        AddText(command, "$keyName", clientKey.KeyName);
        AddText(command, "$keyIdentifier", clientKey.KeyIdentifier);
        AddText(command, "$credentialType", clientKey.CredentialType);
        AddText(command, "$secretHashAlgorithm", clientKey.SecretHashAlgorithm);
        AddText(command, "$secretHash", clientKey.SecretHash);
        AddNullableText(command, "$secretHint", clientKey.SecretHint);
        AddBoolean(command, "$isEnabled", clientKey.IsEnabled);
        AddText(command, "$createdAtUtc", FormatTimestamp(clientKey.CreatedAtUtc));
        AddText(command, "$updatedAtUtc", FormatTimestamp(clientKey.UpdatedAtUtc));
        AddNullableText(command, "$expiresAtUtc", clientKey.ExpiresAtUtc is null ? null : FormatTimestamp(clientKey.ExpiresAtUtc.Value));
        AddNullableText(command, "$revokedAtUtc", clientKey.RevokedAtUtc is null ? null : FormatTimestamp(clientKey.RevokedAtUtc.Value));
        AddNullableText(command, "$revokedReason", clientKey.RevokedReason);
        AddNullableText(command, "$lastUsedAtUtc", clientKey.LastUsedAtUtc is null ? null : FormatTimestamp(clientKey.LastUsedAtUtc.Value));

        await command.ExecuteNonQueryAsync(cancellationToken);
        await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<bool> TryTouchClientKeyLastUsedAsync(Guid clientKeyId, DateTimeOffset lastUsedAtUtc, TimeSpan minimumInterval, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            UPDATE crypto_api_client_keys
            SET last_used_at_utc = $lastUsedAtUtc
            WHERE client_key_id = $clientKeyId
              AND (last_used_at_utc IS NULL OR last_used_at_utc < $minimumLastUsedAtUtc);
            """;
        AddText(command, "$clientKeyId", clientKeyId.ToString("D", CultureInfo.InvariantCulture));
        AddText(command, "$lastUsedAtUtc", FormatTimestamp(lastUsedAtUtc));
        AddText(command, "$minimumLastUsedAtUtc", FormatTimestamp(lastUsedAtUtc - minimumInterval));

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task UpsertKeyAliasAsync(CryptoApiKeyAliasRecord keyAlias, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO crypto_api_key_aliases (
                alias_id,
                alias_name,
                device_route,
                slot_id,
                object_label,
                object_id_hex,
                notes,
                is_enabled,
                created_at_utc,
                updated_at_utc)
            VALUES (
                $aliasId,
                $aliasName,
                $deviceRoute,
                $slotId,
                $objectLabel,
                $objectIdHex,
                $notes,
                $isEnabled,
                $createdAtUtc,
                $updatedAtUtc)
            ON CONFLICT(alias_id) DO UPDATE SET
                alias_name = excluded.alias_name,
                device_route = excluded.device_route,
                slot_id = excluded.slot_id,
                object_label = excluded.object_label,
                object_id_hex = excluded.object_id_hex,
                notes = excluded.notes,
                is_enabled = excluded.is_enabled,
                updated_at_utc = excluded.updated_at_utc;
            """;
        AddText(command, "$aliasId", keyAlias.AliasId.ToString("D", CultureInfo.InvariantCulture));
        AddText(command, "$aliasName", keyAlias.AliasName);
        AddNullableText(command, "$deviceRoute", keyAlias.DeviceRoute);
        AddNullableInt64(command, "$slotId", keyAlias.SlotId is null ? null : checked((long)keyAlias.SlotId.Value));
        AddNullableText(command, "$objectLabel", keyAlias.ObjectLabel);
        AddNullableText(command, "$objectIdHex", keyAlias.ObjectIdHex);
        AddNullableText(command, "$notes", keyAlias.Notes);
        AddBoolean(command, "$isEnabled", keyAlias.IsEnabled);
        AddText(command, "$createdAtUtc", FormatTimestamp(keyAlias.CreatedAtUtc));
        AddText(command, "$updatedAtUtc", FormatTimestamp(keyAlias.UpdatedAtUtc));

        await command.ExecuteNonQueryAsync(cancellationToken);
        await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task UpsertPolicyAsync(CryptoApiPolicyRecord policy, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using SqliteCommand command = connection.CreateCommand();
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
                $policyId,
                $policyName,
                $description,
                $revision,
                $documentJson,
                $isEnabled,
                $createdAtUtc,
                $updatedAtUtc)
            ON CONFLICT(policy_id) DO UPDATE SET
                policy_name = excluded.policy_name,
                description = excluded.description,
                revision = excluded.revision,
                document_json = excluded.document_json,
                is_enabled = excluded.is_enabled,
                updated_at_utc = excluded.updated_at_utc;
            """;
        AddText(command, "$policyId", policy.PolicyId.ToString("D", CultureInfo.InvariantCulture));
        AddText(command, "$policyName", policy.PolicyName);
        AddNullableText(command, "$description", policy.Description);
        command.Parameters.AddWithValue("$revision", policy.Revision);
        AddText(command, "$documentJson", policy.DocumentJson);
        AddBoolean(command, "$isEnabled", policy.IsEnabled);
        AddText(command, "$createdAtUtc", FormatTimestamp(policy.CreatedAtUtc));
        AddText(command, "$updatedAtUtc", FormatTimestamp(policy.UpdatedAtUtc));

        await command.ExecuteNonQueryAsync(cancellationToken);
        await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task ReplaceClientPolicyBindingsAsync(Guid clientId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await DeleteBindingsAsync(connection, transaction, "crypto_api_client_policy_bindings", "client_id", clientId, cancellationToken);
        foreach (Guid policyId in policyIds.Distinct())
        {
            await using SqliteCommand insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO crypto_api_client_policy_bindings (client_id, policy_id, bound_at_utc)
                VALUES ($clientId, $policyId, $boundAtUtc);
                """;
            AddText(insert, "$clientId", clientId.ToString("D", CultureInfo.InvariantCulture));
            AddText(insert, "$policyId", policyId.ToString("D", CultureInfo.InvariantCulture));
            AddText(insert, "$boundAtUtc", FormatTimestamp(DateTimeOffset.UtcNow));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task ReplaceKeyAliasPolicyBindingsAsync(Guid aliasId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await DeleteBindingsAsync(connection, transaction, "crypto_api_key_alias_policy_bindings", "alias_id", aliasId, cancellationToken);
        foreach (Guid policyId in policyIds.Distinct())
        {
            await using SqliteCommand insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO crypto_api_key_alias_policy_bindings (alias_id, policy_id, bound_at_utc)
                VALUES ($aliasId, $policyId, $boundAtUtc);
                """;
            AddText(insert, "$aliasId", aliasId.ToString("D", CultureInfo.InvariantCulture));
            AddText(insert, "$policyId", policyId.ToString("D", CultureInfo.InvariantCulture));
            AddText(insert, "$boundAtUtc", FormatTimestamp(DateTimeOffset.UtcNow));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await IncrementAuthStateRevisionAsync(connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<CryptoApiSharedStateSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        await EnsureConfiguredAndInitializedAsync(cancellationToken);

        await using SqliteConnection connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await PrepareConnectionAsync(connection, cancellationToken);

        return new CryptoApiSharedStateSnapshot(
            Clients: await ReadClientsAsync(connection, cancellationToken),
            ClientKeys: await ReadClientKeysAsync(connection, cancellationToken),
            KeyAliases: await ReadKeyAliasesAsync(connection, cancellationToken),
            Policies: await ReadPoliciesAsync(connection, cancellationToken),
            ClientPolicyBindings: await ReadClientPolicyBindingsAsync(connection, cancellationToken),
            KeyAliasPolicyBindings: await ReadKeyAliasPolicyBindingsAsync(connection, cancellationToken));
    }

    private bool IsConfigured()
        => !string.IsNullOrWhiteSpace(_options.ConnectionString);

    private CryptoApiSharedStateStatus CreateUnconfiguredStatus()
        => new(
            Configured: false,
            Provider: CryptoApiSharedPersistenceDefaults.SqliteProvider,
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

    private SqliteConnection CreateConnection()
        => new(_options.ConnectionString);

    private async Task PrepareConnectionAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await ExecutePragmaAsync(connection, "PRAGMA foreign_keys = ON;", cancellationToken);
        await ExecutePragmaAsync(connection, "PRAGMA busy_timeout = 5000;", cancellationToken);
    }

    private static async Task ConfigureDatabaseAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await ExecutePragmaAsync(connection, "PRAGMA journal_mode = WAL;", cancellationToken);
    }

    private static async Task ExecutePragmaAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task EnsureSchemaAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS crypto_api_clients (
                client_id TEXT PRIMARY KEY,
                client_name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                application_type TEXT NOT NULL DEFAULT 'service',
                authentication_mode TEXT NOT NULL,
                is_enabled INTEGER NOT NULL,
                notes TEXT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crypto_api_client_keys (
                client_key_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                key_name TEXT NOT NULL,
                key_identifier TEXT NOT NULL UNIQUE,
                credential_type TEXT NOT NULL,
                secret_hash_algorithm TEXT NOT NULL DEFAULT 'legacy-placeholder',
                secret_hash TEXT NOT NULL,
                secret_hint TEXT NULL,
                is_enabled INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NULL,
                revoked_at_utc TEXT NULL,
                revoked_reason TEXT NULL,
                last_used_at_utc TEXT NULL,
                FOREIGN KEY(client_id) REFERENCES crypto_api_clients(client_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS crypto_api_key_aliases (
                alias_id TEXT PRIMARY KEY,
                alias_name TEXT NOT NULL UNIQUE,
                device_route TEXT NULL,
                slot_id INTEGER NULL,
                object_label TEXT NULL,
                object_id_hex TEXT NULL,
                notes TEXT NULL,
                is_enabled INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crypto_api_policies (
                policy_id TEXT PRIMARY KEY,
                policy_name TEXT NOT NULL UNIQUE,
                description TEXT NULL,
                revision INTEGER NOT NULL,
                document_json TEXT NOT NULL,
                is_enabled INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crypto_api_client_policy_bindings (
                client_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                bound_at_utc TEXT NOT NULL,
                PRIMARY KEY (client_id, policy_id),
                FOREIGN KEY(client_id) REFERENCES crypto_api_clients(client_id) ON DELETE CASCADE,
                FOREIGN KEY(policy_id) REFERENCES crypto_api_policies(policy_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS crypto_api_key_alias_policy_bindings (
                alias_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                bound_at_utc TEXT NOT NULL,
                PRIMARY KEY (alias_id, policy_id),
                FOREIGN KEY(alias_id) REFERENCES crypto_api_key_aliases(alias_id) ON DELETE CASCADE,
                FOREIGN KEY(policy_id) REFERENCES crypto_api_policies(policy_id) ON DELETE CASCADE
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

            INSERT OR IGNORE INTO crypto_api_metadata (metadata_key, metadata_value)
            VALUES ('auth_state_revision', '1');
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);

        await EnsureColumnExistsAsync(connection, "crypto_api_clients", "application_type", "TEXT NOT NULL DEFAULT 'service'", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_client_keys", "secret_hash_algorithm", "TEXT NOT NULL DEFAULT 'legacy-placeholder'", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_client_keys", "revoked_at_utc", "TEXT NULL", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_client_keys", "revoked_reason", "TEXT NULL", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_client_keys", "last_used_at_utc", "TEXT NULL", cancellationToken);
        await EnsureColumnExistsAsync(connection, "crypto_api_key_aliases", "device_route", "TEXT NULL", cancellationToken);

        await using SqliteCommand versionCommand = connection.CreateCommand();
        versionCommand.CommandText = $"PRAGMA user_version = {CryptoApiSharedStateConstants.SchemaVersion};";
        await versionCommand.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task EnsureColumnExistsAsync(SqliteConnection connection, string tableName, string columnName, string sqlTypeClause, CancellationToken cancellationToken)
    {
        await using SqliteCommand pragma = connection.CreateCommand();
        pragma.CommandText = $"PRAGMA table_info({tableName});";
        await using SqliteDataReader reader = await pragma.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (string.Equals(reader.GetString(1), columnName, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }

        await using SqliteCommand alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE {tableName} ADD COLUMN {columnName} {sqlTypeClause};";
        await alter.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<int> CountRowsAsync(SqliteConnection connection, string tableName, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {tableName};";
        object? value = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(value, CultureInfo.InvariantCulture);
    }

    private static async Task<int> GetSchemaVersionAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        object? value = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(value, CultureInfo.InvariantCulture);
    }

    private static async Task<long> GetAuthStateRevisionCoreAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT metadata_value FROM crypto_api_metadata WHERE metadata_key = $metadataKey;";
        AddText(command, "$metadataKey", AuthStateRevisionMetadataKey);
        object? value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null
            ? 1
            : Convert.ToInt64(value, CultureInfo.InvariantCulture);
    }

    private static async Task<Guid[]> ReadClientBoundPolicyIdsAsync(SqliteConnection connection, Guid clientId, CancellationToken cancellationToken)
    {
        List<Guid> policyIds = [];
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT policy_id
            FROM crypto_api_client_policy_bindings
            WHERE client_id = $clientId
            ORDER BY policy_id;
            """;
        AddText(command, "$clientId", clientId.ToString("D", CultureInfo.InvariantCulture));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            policyIds.Add(Guid.Parse(reader.GetString(0)));
        }

        return policyIds.ToArray();
    }

    private static async Task<CryptoApiClientRecord?> ReadClientByIdAsync(SqliteConnection connection, Guid clientId, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_id, client_name, display_name, application_type, authentication_mode, is_enabled, notes, created_at_utc, updated_at_utc
            FROM crypto_api_clients
            WHERE client_id = $clientId
            LIMIT 1;
            """;
        AddText(command, "$clientId", clientId.ToString("D", CultureInfo.InvariantCulture));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new CryptoApiClientRecord(
            ClientId: Guid.Parse(reader.GetString(0)),
            ClientName: reader.GetString(1),
            DisplayName: reader.GetString(2),
            ApplicationType: reader.GetString(3),
            AuthenticationMode: reader.GetString(4),
            IsEnabled: reader.GetBoolean(5),
            Notes: reader.IsDBNull(6) ? null : reader.GetString(6),
            CreatedAtUtc: ParseTimestamp(reader.GetString(7)),
            UpdatedAtUtc: ParseTimestamp(reader.GetString(8)));
    }

    private static async Task<CryptoApiKeyAliasRecord?> ReadKeyAliasByNameAsync(SqliteConnection connection, string aliasName, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT alias_id, alias_name, device_route, slot_id, object_label, object_id_hex, notes, is_enabled, created_at_utc, updated_at_utc
            FROM crypto_api_key_aliases
            WHERE alias_name = $aliasName COLLATE NOCASE
            LIMIT 1;
            """;
        AddText(command, "$aliasName", aliasName);

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new CryptoApiKeyAliasRecord(
            AliasId: Guid.Parse(reader.GetString(0)),
            AliasName: reader.GetString(1),
            DeviceRoute: reader.IsDBNull(2) ? null : reader.GetString(2),
            SlotId: reader.IsDBNull(3) ? null : checked((ulong)reader.GetInt64(3)),
            ObjectLabel: reader.IsDBNull(4) ? null : reader.GetString(4),
            ObjectIdHex: reader.IsDBNull(5) ? null : reader.GetString(5),
            Notes: reader.IsDBNull(6) ? null : reader.GetString(6),
            IsEnabled: reader.GetBoolean(7),
            CreatedAtUtc: ParseTimestamp(reader.GetString(8)),
            UpdatedAtUtc: ParseTimestamp(reader.GetString(9)));
    }

    private static async Task<IReadOnlyList<CryptoApiPolicyRecord>> ReadSharedPoliciesAsync(SqliteConnection connection, Guid clientId, Guid aliasId, CancellationToken cancellationToken)
    {
        List<CryptoApiPolicyRecord> policies = [];
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT DISTINCT p.policy_id, p.policy_name, p.description, p.revision, p.document_json, p.is_enabled, p.created_at_utc, p.updated_at_utc
            FROM crypto_api_policies p
            INNER JOIN crypto_api_client_policy_bindings cpb ON cpb.policy_id = p.policy_id
            INNER JOIN crypto_api_key_alias_policy_bindings kapb ON kapb.policy_id = p.policy_id
            WHERE cpb.client_id = $clientId
              AND kapb.alias_id = $aliasId
              AND p.is_enabled = 1
            ORDER BY p.policy_name;
            """;
        AddText(command, "$clientId", clientId.ToString("D", CultureInfo.InvariantCulture));
        AddText(command, "$aliasId", aliasId.ToString("D", CultureInfo.InvariantCulture));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            policies.Add(new CryptoApiPolicyRecord(
                PolicyId: Guid.Parse(reader.GetString(0)),
                PolicyName: reader.GetString(1),
                Description: reader.IsDBNull(2) ? null : reader.GetString(2),
                Revision: reader.GetInt32(3),
                DocumentJson: reader.GetString(4),
                IsEnabled: reader.GetBoolean(5),
                CreatedAtUtc: ParseTimestamp(reader.GetString(6)),
                UpdatedAtUtc: ParseTimestamp(reader.GetString(7))));
        }

        return policies;
    }

    private static async Task IncrementAuthStateRevisionAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE crypto_api_metadata
            SET metadata_value = CAST(CAST(metadata_value AS INTEGER) + 1 AS TEXT)
            WHERE metadata_key = $metadataKey;
            """;
        AddText(command, "$metadataKey", AuthStateRevisionMetadataKey);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private string? GetConnectionTarget()
    {
        SqliteConnectionStringBuilder builder = new(_options.ConnectionString);
        return string.IsNullOrWhiteSpace(builder.DataSource)
            ? null
            : builder.DataSource;
    }

    private static async Task DeleteBindingsAsync(SqliteConnection connection, SqliteTransaction transaction, string tableName, string keyColumn, Guid keyValue, CancellationToken cancellationToken)
    {
        await using SqliteCommand delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = $"DELETE FROM {tableName} WHERE {keyColumn} = $keyValue;";
        AddText(delete, "$keyValue", keyValue.ToString("D", CultureInfo.InvariantCulture));
        await delete.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<IReadOnlyList<CryptoApiClientRecord>> ReadClientsAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiClientRecord> clients = [];
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_id, client_name, display_name, application_type, authentication_mode, is_enabled, notes, created_at_utc, updated_at_utc
            FROM crypto_api_clients
            ORDER BY client_name;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            clients.Add(new CryptoApiClientRecord(
                ClientId: Guid.Parse(reader.GetString(0)),
                ClientName: reader.GetString(1),
                DisplayName: reader.GetString(2),
                ApplicationType: reader.GetString(3),
                AuthenticationMode: reader.GetString(4),
                IsEnabled: reader.GetBoolean(5),
                Notes: reader.IsDBNull(6) ? null : reader.GetString(6),
                CreatedAtUtc: ParseTimestamp(reader.GetString(7)),
                UpdatedAtUtc: ParseTimestamp(reader.GetString(8))));
        }

        return clients;
    }

    private static async Task<IReadOnlyList<CryptoApiClientKeyRecord>> ReadClientKeysAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiClientKeyRecord> clientKeys = [];
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_key_id, client_id, key_name, key_identifier, credential_type, secret_hash_algorithm, secret_hash, secret_hint, is_enabled, created_at_utc, updated_at_utc, expires_at_utc, revoked_at_utc, revoked_reason, last_used_at_utc
            FROM crypto_api_client_keys
            ORDER BY key_name;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            clientKeys.Add(new CryptoApiClientKeyRecord(
                ClientKeyId: Guid.Parse(reader.GetString(0)),
                ClientId: Guid.Parse(reader.GetString(1)),
                KeyName: reader.GetString(2),
                KeyIdentifier: reader.GetString(3),
                CredentialType: reader.GetString(4),
                SecretHashAlgorithm: reader.GetString(5),
                SecretHash: reader.GetString(6),
                SecretHint: reader.IsDBNull(7) ? null : reader.GetString(7),
                IsEnabled: reader.GetBoolean(8),
                CreatedAtUtc: ParseTimestamp(reader.GetString(9)),
                UpdatedAtUtc: ParseTimestamp(reader.GetString(10)),
                ExpiresAtUtc: reader.IsDBNull(11) ? null : ParseTimestamp(reader.GetString(11)),
                RevokedAtUtc: reader.IsDBNull(12) ? null : ParseTimestamp(reader.GetString(12)),
                RevokedReason: reader.IsDBNull(13) ? null : reader.GetString(13),
                LastUsedAtUtc: reader.IsDBNull(14) ? null : ParseTimestamp(reader.GetString(14))));
        }

        return clientKeys;
    }

    private static async Task<IReadOnlyList<CryptoApiKeyAliasRecord>> ReadKeyAliasesAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiKeyAliasRecord> aliases = [];
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT alias_id, alias_name, device_route, slot_id, object_label, object_id_hex, notes, is_enabled, created_at_utc, updated_at_utc
            FROM crypto_api_key_aliases
            ORDER BY alias_name;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            aliases.Add(new CryptoApiKeyAliasRecord(
                AliasId: Guid.Parse(reader.GetString(0)),
                AliasName: reader.GetString(1),
                DeviceRoute: reader.IsDBNull(2) ? null : reader.GetString(2),
                SlotId: reader.IsDBNull(3) ? null : checked((ulong)reader.GetInt64(3)),
                ObjectLabel: reader.IsDBNull(4) ? null : reader.GetString(4),
                ObjectIdHex: reader.IsDBNull(5) ? null : reader.GetString(5),
                Notes: reader.IsDBNull(6) ? null : reader.GetString(6),
                IsEnabled: reader.GetBoolean(7),
                CreatedAtUtc: ParseTimestamp(reader.GetString(8)),
                UpdatedAtUtc: ParseTimestamp(reader.GetString(9))));
        }

        return aliases;
    }

    private static async Task<IReadOnlyList<CryptoApiPolicyRecord>> ReadPoliciesAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiPolicyRecord> policies = [];
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT policy_id, policy_name, description, revision, document_json, is_enabled, created_at_utc, updated_at_utc
            FROM crypto_api_policies
            ORDER BY policy_name;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            policies.Add(new CryptoApiPolicyRecord(
                PolicyId: Guid.Parse(reader.GetString(0)),
                PolicyName: reader.GetString(1),
                Description: reader.IsDBNull(2) ? null : reader.GetString(2),
                Revision: reader.GetInt32(3),
                DocumentJson: reader.GetString(4),
                IsEnabled: reader.GetBoolean(5),
                CreatedAtUtc: ParseTimestamp(reader.GetString(6)),
                UpdatedAtUtc: ParseTimestamp(reader.GetString(7))));
        }

        return policies;
    }

    private static async Task<IReadOnlyList<CryptoApiClientPolicyBinding>> ReadClientPolicyBindingsAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiClientPolicyBinding> bindings = [];
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_id, policy_id, bound_at_utc
            FROM crypto_api_client_policy_bindings
            ORDER BY client_id, policy_id;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            bindings.Add(new CryptoApiClientPolicyBinding(
                ClientId: Guid.Parse(reader.GetString(0)),
                PolicyId: Guid.Parse(reader.GetString(1)),
                BoundAtUtc: ParseTimestamp(reader.GetString(2))));
        }

        return bindings;
    }

    private static async Task<IReadOnlyList<CryptoApiKeyAliasPolicyBinding>> ReadKeyAliasPolicyBindingsAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        List<CryptoApiKeyAliasPolicyBinding> bindings = [];
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT alias_id, policy_id, bound_at_utc
            FROM crypto_api_key_alias_policy_bindings
            ORDER BY alias_id, policy_id;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            bindings.Add(new CryptoApiKeyAliasPolicyBinding(
                AliasId: Guid.Parse(reader.GetString(0)),
                PolicyId: Guid.Parse(reader.GetString(1)),
                BoundAtUtc: ParseTimestamp(reader.GetString(2))));
        }

        return bindings;
    }

    private static string FormatTimestamp(DateTimeOffset value)
        => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTimestamp(string value)
        => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static void AddText(SqliteCommand command, string parameterName, string value)
        => command.Parameters.AddWithValue(parameterName, value);

    private static void AddNullableText(SqliteCommand command, string parameterName, string? value)
        => command.Parameters.AddWithValue(parameterName, value ?? (object)DBNull.Value);

    private static void AddNullableInt64(SqliteCommand command, string parameterName, long? value)
        => command.Parameters.AddWithValue(parameterName, value ?? (object)DBNull.Value);

    private static void AddBoolean(SqliteCommand command, string parameterName, bool value)
        => command.Parameters.AddWithValue(parameterName, value);
}
