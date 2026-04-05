using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Observability;
using StackExchange.Redis;

namespace Pkcs11Wrapper.CryptoApi.Caching;

public sealed class RedisCryptoApiDistributedHotPathCache : ICryptoApiDistributedHotPathCache, IAsyncDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly TimeProvider _timeProvider;
    private readonly ILogger<RedisCryptoApiDistributedHotPathCache> _logger;
    private readonly CryptoApiRequestPathCachingOptions _options;
    private readonly CryptoApiRequestPathRedisOptions _redisOptions;
    private readonly SemaphoreSlim _connectionGate = new(1, 1);
    private readonly CryptoApiMetrics? _metrics;

    private IConnectionMultiplexer? _connection;
    private DateTimeOffset _nextConnectAttemptUtc;

    public RedisCryptoApiDistributedHotPathCache(
        IOptions<CryptoApiRequestPathCachingOptions> options,
        TimeProvider timeProvider,
        ILogger<RedisCryptoApiDistributedHotPathCache> logger,
        CryptoApiMetrics? metrics = null)
    {
        _timeProvider = timeProvider;
        _logger = logger;
        _options = options.Value;
        _redisOptions = _options.Redis ?? new CryptoApiRequestPathRedisOptions();
        _metrics = metrics;
    }

    public bool Enabled
        => _redisOptions.Enabled && !string.IsNullOrWhiteSpace(_redisOptions.Configuration);

    public async Task<long?> GetAuthStateRevisionAsync(CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "miss";
        IDatabase? database = await TryGetDatabaseAsync(cancellationToken);
        if (database is null)
        {
            _metrics?.RecordDistributedCacheRequest("get_auth_state_revision", "unavailable", stopwatch.Elapsed);
            return null;
        }

        try
        {
            RedisValue value = await database.StringGetAsync(GetAuthStateRevisionKey()).WaitAsync(cancellationToken);
            string? text = value.IsNullOrEmpty ? null : value.ToString();
            if (string.IsNullOrWhiteSpace(text) || !long.TryParse(text, out long parsed))
            {
                result = "miss";
                return null;
            }

            result = "hit";
            return parsed;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = "error";
            LogRedisFailure(ex, "read auth-state revision");
            return null;
        }
        finally
        {
            _metrics?.RecordDistributedCacheRequest("get_auth_state_revision", result, stopwatch.Elapsed);
        }
    }

    public async Task SetAuthStateRevisionAsync(long authStateRevision, CancellationToken cancellationToken = default)
    {
        if (authStateRevision <= 0)
        {
            return;
        }

        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "success";
        IDatabase? database = await TryGetDatabaseAsync(cancellationToken);
        if (database is null)
        {
            _metrics?.RecordDistributedCacheRequest("set_auth_state_revision", "unavailable", stopwatch.Elapsed);
            return;
        }

        try
        {
            _ = await database.StringSetAsync(
                    GetAuthStateRevisionKey(),
                    authStateRevision.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    _redisOptions.AuthStateRevisionTtl)
                .WaitAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = "error";
            LogRedisFailure(ex, "write auth-state revision");
        }
        finally
        {
            _metrics?.RecordDistributedCacheRequest("set_auth_state_revision", result, stopwatch.Elapsed);
        }
    }

    public async Task<CryptoApiAuthenticatedClient?> GetAuthenticatedClientAsync(
        long authStateRevision,
        string keyIdentifier,
        string secretFingerprint,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "miss";
        IDatabase? database = await TryGetDatabaseAsync(cancellationToken);
        if (database is null)
        {
            _metrics?.RecordDistributedCacheRequest("get_authenticated_client", "unavailable", stopwatch.Elapsed);
            return null;
        }

        try
        {
            RedisValue value = await database.StringGetAsync(GetAuthenticationKey(authStateRevision, keyIdentifier, secretFingerprint)).WaitAsync(cancellationToken);
            if (value.IsNullOrEmpty)
            {
                result = "miss";
                return null;
            }

            CryptoApiAuthenticatedClient? cached = JsonSerializer.Deserialize<CryptoApiAuthenticatedClient>(value.ToString()!, SerializerOptions);
            if (cached is null)
            {
                result = "miss";
                return null;
            }

            if (cached.ExpiresAtUtc is DateTimeOffset expiresAtUtc && expiresAtUtc <= now)
            {
                result = "expired";
                return null;
            }

            result = "hit";
            return cached with { AuthenticatedAtUtc = now };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = "error";
            LogRedisFailure(ex, "read distributed authenticated-client entry");
            return null;
        }
        finally
        {
            _metrics?.RecordDistributedCacheRequest("get_authenticated_client", result, stopwatch.Elapsed);
        }
    }

    public async Task SetAuthenticatedClientAsync(
        long authStateRevision,
        string keyIdentifier,
        string secretFingerprint,
        CryptoApiAuthenticatedClient authenticatedClient,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticatedClient);

        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "success";
        IDatabase? database = await TryGetDatabaseAsync(cancellationToken);
        if (database is null)
        {
            _metrics?.RecordDistributedCacheRequest("set_authenticated_client", "unavailable", stopwatch.Elapsed);
            return;
        }

        try
        {
            _ = await database.StringSetAsync(
                    GetAuthenticationKey(authStateRevision, keyIdentifier, secretFingerprint),
                    JsonSerializer.Serialize(authenticatedClient, SerializerOptions),
                    _options.EntryTtl)
                .WaitAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = "error";
            LogRedisFailure(ex, "write distributed authenticated-client entry");
        }
        finally
        {
            _metrics?.RecordDistributedCacheRequest("set_authenticated_client", result, stopwatch.Elapsed);
        }
    }

    public async Task<CryptoApiAuthorizedKeyOperation?> GetAuthorizedOperationAsync(
        long authStateRevision,
        Guid clientId,
        string aliasName,
        string operation,
        CryptoApiAuthenticatedClient client,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "miss";
        IDatabase? database = await TryGetDatabaseAsync(cancellationToken);
        if (database is null)
        {
            _metrics?.RecordDistributedCacheRequest("get_authorized_operation", "unavailable", stopwatch.Elapsed);
            return null;
        }

        try
        {
            RedisValue value = await database.StringGetAsync(GetAuthorizationKey(authStateRevision, clientId, aliasName, operation)).WaitAsync(cancellationToken);
            if (value.IsNullOrEmpty)
            {
                result = "miss";
                return null;
            }

            AuthorizationCachePayload? payload = JsonSerializer.Deserialize<AuthorizationCachePayload>(value.ToString()!, SerializerOptions);
            if (payload is null)
            {
                result = "miss";
                return null;
            }

            result = "hit";
            return new CryptoApiAuthorizedKeyOperation(
                Client: client,
                Operation: payload.Operation,
                AliasId: payload.AliasId,
                AliasName: payload.AliasName,
                RoutePlan: payload.RoutePlan,
                MatchedPolicies: payload.MatchedPolicies,
                AuthorizedAtUtc: now);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = "error";
            LogRedisFailure(ex, "read distributed authorization entry");
            return null;
        }
        finally
        {
            _metrics?.RecordDistributedCacheRequest("get_authorized_operation", result, stopwatch.Elapsed);
        }
    }

    public async Task SetAuthorizedOperationAsync(
        long authStateRevision,
        Guid clientId,
        CryptoApiAuthorizedKeyOperation authorization,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "success";
        IDatabase? database = await TryGetDatabaseAsync(cancellationToken);
        if (database is null)
        {
            _metrics?.RecordDistributedCacheRequest("set_authorized_operation", "unavailable", stopwatch.Elapsed);
            return;
        }

        AuthorizationCachePayload payload = new(
            authorization.Operation,
            authorization.AliasId,
            authorization.AliasName,
            authorization.RoutePlan,
            authorization.MatchedPolicies);

        try
        {
            _ = await database.StringSetAsync(
                    GetAuthorizationKey(authStateRevision, clientId, authorization.AliasName, authorization.Operation),
                    JsonSerializer.Serialize(payload, SerializerOptions),
                    _options.EntryTtl)
                .WaitAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = "error";
            LogRedisFailure(ex, "write distributed authorization entry");
        }
        finally
        {
            _metrics?.RecordDistributedCacheRequest("set_authorized_operation", result, stopwatch.Elapsed);
        }
    }

    public async Task<bool?> TryAcquireLastUsedRefreshLeaseAsync(
        Guid clientKeyId,
        DateTimeOffset now,
        TimeSpan minimumInterval,
        CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string result = "unavailable";
        IDatabase? database = await TryGetDatabaseAsync(cancellationToken);
        if (database is null)
        {
            _metrics?.RecordDistributedCacheRequest("acquire_last_used_refresh_lease", "unavailable", stopwatch.Elapsed);
            return null;
        }

        try
        {
            bool acquired = await database.StringSetAsync(
                    GetLastUsedLeaseKey(clientKeyId),
                    now.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
                    minimumInterval,
                    when: When.NotExists)
                .WaitAsync(cancellationToken);
            result = acquired ? "acquired" : "denied";
            return acquired;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = "error";
            LogRedisFailure(ex, "acquire last-used refresh lease");
            return null;
        }
        finally
        {
            _metrics?.RecordDistributedCacheRequest("acquire_last_used_refresh_lease", result, stopwatch.Elapsed);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _connectionGate.Dispose();

        if (_connection is not null)
        {
            await _connection.DisposeAsync();
        }
    }

    private async Task<IDatabase?> TryGetDatabaseAsync(CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            return null;
        }

        IConnectionMultiplexer? connection = _connection;
        if (connection is not null && connection.IsConnected)
        {
            return connection.GetDatabase();
        }

        await _connectionGate.WaitAsync(cancellationToken);
        try
        {
            connection = _connection;
            if (connection is not null && connection.IsConnected)
            {
                return connection.GetDatabase();
            }

            DateTimeOffset now = _timeProvider.GetUtcNow();
            if (_nextConnectAttemptUtc > now)
            {
                return null;
            }

            ConfigurationOptions configuration = ConfigurationOptions.Parse(_redisOptions.Configuration!, true);
            configuration.AbortOnConnectFail = false;
            configuration.ConnectTimeout = _redisOptions.ConnectTimeoutMilliseconds;
            configuration.SyncTimeout = _redisOptions.OperationTimeoutMilliseconds;
            configuration.AsyncTimeout = _redisOptions.OperationTimeoutMilliseconds;
            configuration.ClientName ??= "Pkcs11Wrapper.CryptoApi";

            _connection = await ConnectionMultiplexer.ConnectAsync(configuration).WaitAsync(cancellationToken);
            _nextConnectAttemptUtc = DateTimeOffset.MinValue;
            return _connection.GetDatabase();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _nextConnectAttemptUtc = _timeProvider.GetUtcNow().AddSeconds(5);
            LogRedisFailure(ex, "connect to Redis hot-path cache");
            return null;
        }
        finally
        {
            _connectionGate.Release();
        }
    }

    private void LogRedisFailure(Exception ex, string operation)
        => _logger.LogDebug(ex, "Crypto API Redis hot-path accelerator could not {Operation}; falling back to source-of-truth/shared-store behavior.", operation);

    private string GetAuthStateRevisionKey()
        => $"{_redisOptions.InstanceName}auth-revision";

    private string GetAuthenticationKey(long authStateRevision, string keyIdentifier, string secretFingerprint)
        => $"{_redisOptions.InstanceName}auth:{authStateRevision}:{HashCompositeKey(keyIdentifier, secretFingerprint)}";

    private string GetAuthorizationKey(long authStateRevision, Guid clientId, string aliasName, string operation)
        => $"{_redisOptions.InstanceName}authorize:{authStateRevision}:{HashCompositeKey(clientId.ToString("N"), aliasName, operation)}";

    private string GetLastUsedLeaseKey(Guid clientKeyId)
        => $"{_redisOptions.InstanceName}last-used:{clientKeyId:N}";

    private static string HashCompositeKey(params string[] values)
    {
        using SHA256 sha256 = SHA256.Create();
        byte[] data = Encoding.UTF8.GetBytes(string.Join('\n', values));
        return Convert.ToHexString(sha256.ComputeHash(data));
    }

    private sealed record AuthorizationCachePayload(
        string Operation,
        Guid AliasId,
        string AliasName,
        CryptoApiRoutePlan RoutePlan,
        IReadOnlyList<CryptoApiMatchedPolicy> MatchedPolicies);
}
